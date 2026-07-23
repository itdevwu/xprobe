#!/usr/bin/perl
use strict;
use warnings;

use Errno qw(EINTR);
use Fcntl qw(O_CREAT O_EXCL O_RDONLY O_RDWR O_WRONLY SEEK_SET);
use File::Find qw(find);
use IO::Handle;
use JSON::PP ();
use POSIX qw(WNOHANG _exit);
use Time::HiRes qw(CLOCK_MONOTONIC clock_gettime usleep);

use constant {
    BASELINE_SECONDS      => 0.35,
    INVENTORY_DURATION_MS => 500,
    MEASURE_DURATION_MS   => 650,
    COLLECTION_WARMUP_US  => 150_000,
    COLLECTION_SAMPLE_US  => 350_000,
    COMMAND_TIMEOUT_MS    => 15_000,
    CONTROL_SIZE          => 24,
    READY_OFFSET          => 0,
    STOP_OFFSET           => 8,
    ITERATIONS_OFFSET     => 16,
};

my $JSON = JSON::PP->new->canonical(1);
my $OUTPUT_DIRECTORY;

END {
    if (defined($OUTPUT_DIRECTORY) && -d $OUTPUT_DIRECTORY
        && defined($ENV{XPROBE_HOST_UID}) && defined($ENV{XPROBE_HOST_GID})) {
        my @paths;
        find({wanted => sub { push @paths, $File::Find::name }, no_chdir => 1},
            $OUTPUT_DIRECTORY);
        my $changed = chown(
            0 + $ENV{XPROBE_HOST_UID}, 0 + $ENV{XPROBE_HOST_GID}, @paths);
        warn "failed to restore benchmark artifact ownership\n"
            if $changed != @paths;
    }
}

sub fail {
    my ($message) = @_;
    die "$message\n";
}

sub require_condition {
    my ($condition, $message) = @_;
    fail($message) unless $condition;
}

sub monotonic_ns {
    return int(clock_gettime(CLOCK_MONOTONIC) * 1_000_000_000);
}

sub read_text {
    my ($path) = @_;
    open my $input, '<', $path or fail("unable to read $path: $!");
    local $/;
    my $content = <$input>;
    close $input or fail("unable to close $path: $!");
    return defined($content) ? $content : '';
}

sub write_text {
    my ($path, $content) = @_;
    open my $output, '>', $path or fail("unable to write $path: $!");
    print {$output} $content or fail("unable to write $path: $!");
    close $output or fail("unable to close $path: $!");
}

sub write_json {
    my ($path, $value) = @_;
    write_text($path, $JSON->encode($value) . "\n");
}

sub procfs_start_time {
    my ($pid) = @_;
    my $path = "/proc/$pid/stat";
    my $stat = read_text($path);
    my $close_parenthesis = rindex($stat, ')');
    require_condition($close_parenthesis >= 0, "malformed procfs stat for PID $pid");
    my $tail = substr($stat, $close_parenthesis + 2);
    my @fields = split /\s+/, $tail;
    require_condition(@fields > 19 && $fields[19] =~ /^\d+$/,
        "malformed procfs start time for PID $pid");
    return 0 + $fields[19];
}

sub verify_identity {
    my ($worker, $phase) = @_;
    require_condition(defined($worker->{pid}),
        "worker $worker->{ordinal} has no PID during $phase");
    require_condition(defined($worker->{process_start_time}),
        "worker $worker->{ordinal} has no procfs start time during $phase");
    my $current = procfs_start_time($worker->{pid});
    require_condition($current == $worker->{process_start_time},
        "worker $worker->{ordinal} PID $worker->{pid} identity mismatch during $phase: "
        . "expected start time $worker->{process_start_time}, found $current");
}

sub worker_stem {
    my ($worker) = @_;
    require_condition(defined($worker->{pid}), 'worker has no PID for artifact naming');
    require_condition(defined($worker->{process_start_time}),
        'worker has no start time for artifact naming');
    return "worker-$worker->{pid}-$worker->{process_start_time}";
}

sub worker_path {
    my ($batch_dir, $worker, $suffix) = @_;
    return "$batch_dir/" . worker_stem($worker) . "-$suffix";
}

sub rename_worker_startup_files {
    my ($batch_dir, $worker) = @_;
    my $control_path = worker_path($batch_dir, $worker, 'control');
    my $stdout_path = worker_path($batch_dir, $worker, 'fixture.stdout');
    my $stderr_path = worker_path($batch_dir, $worker, 'fixture.stderr');
    rename $worker->{control_path}, $control_path
        or fail("unable to rename worker control file: $!");
    rename $worker->{stdout_path}, $stdout_path
        or fail("unable to rename worker stdout: $!");
    rename $worker->{stderr_path}, $stderr_path
        or fail("unable to rename worker stderr: $!");
    $worker->{control_path} = $control_path;
    $worker->{stdout_path} = $stdout_path;
    $worker->{stderr_path} = $stderr_path;
}

sub write_control {
    my ($path, $offset, $value) = @_;
    sysopen my $control, $path, O_RDWR
        or fail("unable to open shared control $path: $!");
    sysseek($control, $offset, SEEK_SET) == $offset
        or fail("unable to seek shared control $path: $!");
    my $bytes = pack('Q<', $value);
    syswrite($control, $bytes, length($bytes)) == length($bytes)
        or fail("unable to write shared control $path: $!");
    $control->sync or fail("unable to sync shared control $path: $!");
    close $control or fail("unable to close shared control $path: $!");
}

sub read_control {
    my ($path, $offset) = @_;
    sysopen my $control, $path, O_RDONLY
        or fail("unable to open shared control $path: $!");
    sysseek($control, $offset, SEEK_SET) == $offset
        or fail("unable to seek shared control $path: $!");
    my $bytes = '';
    my $count = sysread($control, $bytes, 8);
    require_condition(defined($count) && $count == 8,
        "unable to read shared control $path: $!");
    close $control or fail("unable to close shared control $path: $!");
    return unpack('Q<', $bytes);
}

sub iteration_snapshot {
    my ($worker) = @_;
    return read_control($worker->{control_path}, ITERATIONS_OFFSET);
}

sub sample_iterations {
    my ($worker, $seconds) = @_;
    my $before = iteration_snapshot($worker);
    my $started = monotonic_ns();
    usleep(int($seconds * 1_000_000));
    my $after = iteration_snapshot($worker);
    my $finished = monotonic_ns();
    my $elapsed_ns = $finished - $started;
    require_condition($after >= $before,
        "worker $worker->{ordinal} iteration counter moved backwards");
    require_condition($after > $before,
        "worker $worker->{ordinal} made no baseline kernel progress");
    return {
        start                 => $before,
        end                   => $after,
        delta                 => $after - $before,
        wall_ns               => $elapsed_ns,
        iterations_per_second => ($after - $before) * 1_000_000_000 / $elapsed_ns,
    };
}

sub artifact {
    my ($path) = @_;
    require_condition(-f $path, "missing artifact $path");
    return {path => $path, bytes => -s $path};
}

sub warning_present {
    my ($result, $code) = @_;
    require_condition(ref($result->{warnings}) eq 'ARRAY',
        'result warnings are malformed');
    for my $warning (@{$result->{warnings}}) {
        return JSON::PP::true
            if ref($warning) eq 'HASH' && defined($warning->{code})
            && $warning->{code} eq $code;
    }
    return JSON::PP::false;
}

sub load_json {
    my ($path, $description) = @_;
    my $value = eval { $JSON->decode(read_text($path)) };
    fail("malformed $description JSON at $path: $@") if $@;
    require_condition(ref($value) eq 'HASH',
        "malformed $description JSON at $path: expected object");
    require_condition(defined($value->{schema_version})
        && $value->{schema_version} eq '2.0',
        "unexpected schema in $description");
    return $value;
}

sub decode_wait_status {
    my ($status) = @_;
    return 128 + ($status & 127) if ($status & 127);
    return ($status >> 8) & 255;
}

sub launch_command {
    my ($command, $stdout_path, $stderr_path) = @_;
    my $pid = fork();
    fail("fork failed: $!") unless defined($pid);
    if ($pid == 0) {
        open STDOUT, '>', $stdout_path or do {
            print STDERR "unable to open $stdout_path: $!\n";
            _exit(127);
        };
        open STDERR, '>', $stderr_path or do {
            print STDERR "unable to open $stderr_path: $!\n";
            _exit(127);
        };
        exec {$command->[0]} @{$command} or do {
            print STDERR "exec $command->[0] failed: $!\n";
            _exit(127);
        };
    }
    return $pid;
}

sub wait_for_command {
    my ($pid) = @_;
    while (1) {
        my $result = waitpid($pid, 0);
        next if $result < 0 && $! == EINTR;
        fail("waitpid failed for PID $pid: $!") if $result < 0;
        return decode_wait_status($?);
    }
}

sub run_command {
    my ($command, $stdout_path, $stderr_path) = @_;
    return wait_for_command(launch_command($command, $stdout_path, $stderr_path));
}

sub run_checked {
    my ($description, @command) = @_;
    my $status = system {$command[0]} @command;
    fail("$description failed to execute: $!") if $status == -1;
    my $exit_status = decode_wait_status($status);
    require_condition($exit_status == 0,
        "$description failed with exit status $exit_status");
}

sub capture_checked {
    my ($description, @command) = @_;
    open my $input, '-|', @command
        or fail("$description failed to execute: $!");
    local $/;
    my $output = <$input>;
    my $closed = close $input;
    my $status = $?;
    require_condition($closed,
        "$description failed with exit status " . decode_wait_status($status));
    return defined($output) ? $output : '';
}

sub command_for_aggregate {
    my ($xprobe, $agent, $worker, $start_selector, $end_selector, $duration_ms) = @_;
    require_condition(defined($worker->{pid}),
        'cannot construct measurement without a worker PID');
    return [
        $xprobe, 'measure',
        '--pid', $worker->{pid},
        '--agent', $agent,
        '--from', $start_selector,
        '--to', $end_selector,
        '--match', 'exact',
        '--duration-ms', $duration_ms,
        '--timeout-ms', COMMAND_TIMEOUT_MS,
        '--json', '--non-interactive', '--no-color',
        '--aggregate', '--max-groups', 8,
    ];
}

sub write_measurement_spec {
    my ($path, $worker, $start_selector, $end_selector) = @_;
    require_condition(defined($worker->{pid}),
        'cannot write a MeasurementSpec without a worker PID');
    require_condition(defined($worker->{process_start_time}),
        'cannot write a MeasurementSpec without a start time');
    write_json($path, {
        schema_version   => '2.0',
        name             => 'cuda_multiprocess_kernel_duration',
        target           => {
            pid                => $worker->{pid},
            process_start_time => $worker->{process_start_time},
        },
        start_selector   => $start_selector,
        end_selector     => $end_selector,
        match_policy     => 'exact',
        samples          => undef,
        duration_ms      => MEASURE_DURATION_MS,
        timeout_ms       => COMMAND_TIMEOUT_MS,
        max_events       => 200_000,
        measurement_mode => 'exact',
    });
}

sub command_for_spec_measure {
    my ($xprobe, $agent, $spec_path, $events_path) = @_;
    return [
        $xprobe, 'measure',
        '--spec', $spec_path,
        '--agent', $agent,
        '--events-out', $events_path,
        '--json', '--non-interactive', '--no-color',
    ];
}

sub validate_result {
    my ($result, $worker, $start_selector, $end_selector) = @_;
    require_condition($result->{ok} && $result->{valid}, 'selector validation failed');
    require_condition(ref($result->{target}) eq 'HASH',
        'validation result has no target identity');
    require_condition($result->{target}{pid} == $worker->{pid},
        'validation target PID does not match worker');
    require_condition(
        $result->{target}{process_start_time} == $worker->{process_start_time},
        'validation target procfs start time does not match worker');
    require_condition(ref($result->{start}) eq 'HASH'
        && $result->{start}{selector} eq $start_selector,
        'validation start selector mismatch');
    require_condition(ref($result->{end}) eq 'HASH'
        && $result->{end}{selector} eq $end_selector,
        'validation end selector mismatch');
    require_condition(ref($result->{requirements}) eq 'HASH',
        'validation requirements are malformed');
    my $activation = $result->{requirements}{agent_activation};
    require_condition(defined($activation)
        && ($activation eq 'already_loaded' || $activation eq 'injection_required'),
        'unexpected CUDA agent activation requirement');
    my $mutation_warning = warning_present($result, 'TARGET_PROCESS_WILL_BE_MODIFIED');
    require_condition($mutation_warning,
        'validation omitted required target-mutation warning')
        if $activation eq 'injection_required';
    return {
        agent_activation        => $activation,
        target_mutation         => $result->{requirements}{target_mutation},
        target_mutation_warning => $mutation_warning,
        policy_recommendation   => $result->{policy_recommendation},
    };
}

sub validate_exact_result {
    my ($result, $worker) = @_;
    require_condition($result->{ok},
        "worker $worker->{ordinal} measure result is not successful");
    require_condition($result->{status} eq 'completed',
        "worker $worker->{ordinal} capture is incomplete");
    my $collection = $result->{collection};
    require_condition(ref($collection) eq 'HASH',
        'measure collection is malformed');
    require_condition($collection->{completeness} eq 'complete',
        'measure collection is incomplete');
    require_condition($collection->{dropped_events} == 0,
        'measure capture dropped events');
    require_condition($collection->{cuda_events} > 0,
        'measure capture retained no CUDA events');
    my $cupti = $collection->{cupti};
    require_condition(ref($cupti) eq 'HASH',
        'measure result lacks CUPTI quality fields');
    require_condition($cupti->{dropped_records} == 0,
        'measure CUPTI capture dropped records');
    require_condition($cupti->{observed_records} == $cupti->{retained_records},
        'measure CUPTI retained record count is incomplete');
    require_condition($cupti->{retained_records} == $collection->{cuda_events},
        'measure CUDA event count does not match retained records');
    my $measurement = $result->{measurement};
    require_condition(ref($measurement) eq 'HASH',
        'measure result lacks measurement quality');
    require_condition(ref($measurement->{samples}) eq 'HASH'
        && $measurement->{samples}{matched} > 0,
        'measure capture has no matched kernel samples');
    return {
        completeness  => $collection->{completeness},
        cuda_events   => $collection->{cuda_events},
        dropped_events => $collection->{dropped_events},
        cupti         => $cupti,
        samples       => $measurement->{samples},
        correlation   => $result->{correlation},
        clock         => $result->{clock},
    };
}

sub make_worker {
    my ($batch_dir, $ordinal, $fixture) = @_;
    my $control_path = "$batch_dir/worker-$ordinal.control";
    sysopen my $control, $control_path, O_WRONLY | O_CREAT | O_EXCL, 0644
        or fail("unable to create $control_path: $!");
    my $empty = "\0" x CONTROL_SIZE;
    syswrite($control, $empty, length($empty)) == length($empty)
        or fail("unable to initialize $control_path: $!");
    close $control or fail("unable to close $control_path: $!");
    my $worker = {
        ordinal              => $ordinal,
        control_path         => $control_path,
        stdout_path          => "$batch_dir/worker-$ordinal.stdout",
        stderr_path          => "$batch_dir/worker-$ordinal.stderr",
        launched_monotonic_ns => monotonic_ns(),
        files                => {},
    };
    $worker->{process_pid} = launch_command(
        [$fixture, $control_path],
        $worker->{stdout_path},
        $worker->{stderr_path});
    return $worker;
}

sub poll_worker {
    my ($worker) = @_;
    return $worker->{exit_status} if defined($worker->{exit_status});
    my $result = waitpid($worker->{process_pid}, WNOHANG);
    return undef if $result == 0;
    fail("waitpid failed for worker $worker->{ordinal}: $!") if $result < 0;
    $worker->{exit_status} = decode_wait_status($?);
    return $worker->{exit_status};
}

sub wait_for_workers_ready {
    my ($batch_dir, $workers) = @_;
    my $deadline = monotonic_ns() + 10_000_000_000;
    my %pending = map { $_->{ordinal} => $_ } @{$workers};
    while (%pending && monotonic_ns() < $deadline) {
        for my $ordinal (keys %pending) {
            my $worker = $pending{$ordinal};
            my $exit_status = poll_worker($worker);
            fail("worker $ordinal exited before readiness with status $exit_status")
                if defined($exit_status);
            if (read_control($worker->{control_path}, READY_OFFSET) == 1) {
                $worker->{ready_monotonic_ns} = monotonic_ns();
                $worker->{pid} = $worker->{process_pid};
                $worker->{process_start_time} = procfs_start_time($worker->{pid});
                verify_identity($worker, 'startup');
                rename_worker_startup_files($batch_dir, $worker);
                delete $pending{$ordinal};
            }
        }
        usleep(10_000) if %pending;
    }
    require_condition(!%pending,
        'worker readiness timed out for indexes ' . join(',', sort keys %pending));
}

sub stop_workers {
    my ($workers) = @_;
    my @failures;
    for my $worker (@{$workers}) {
        next if defined(poll_worker($worker));
        eval { write_control($worker->{control_path}, STOP_OFFSET, 1); 1 }
            or push @failures,
                "worker $worker->{ordinal} stop signal failed: " . ($@ || 'unknown error');
    }
    my $deadline = monotonic_ns() + 10_000_000_000;
    while (monotonic_ns() < $deadline) {
        my $running = 0;
        for my $worker (@{$workers}) {
            $running++ unless defined(poll_worker($worker));
        }
        last unless $running;
        usleep(10_000);
    }
    for my $worker (@{$workers}) {
        unless (defined(poll_worker($worker))) {
            kill 'KILL', $worker->{process_pid};
            waitpid($worker->{process_pid}, 0);
            $worker->{exit_status} = decode_wait_status($?);
            push @failures,
                "worker $worker->{ordinal} did not stop after its stop signal";
        }
        push @failures,
            "worker $worker->{ordinal} exited with status $worker->{exit_status}"
            if $worker->{exit_status} != 0;
    }
    fail(join('; ', @failures)) if @failures;
}

sub discover_workers {
    my ($batch_dir, $xprobe, $workers) = @_;
    my $root_pid = $$;
    my $root_start_time = procfs_start_time($root_pid);
    my $stdout_path = "$batch_dir/root-$root_pid-$root_start_time-discover.json";
    my $stderr_path = "$batch_dir/root-$root_pid-$root_start_time-discover.stderr";
    my $exit_status = run_command([
        $xprobe, 'discover',
        '--pid', $root_pid,
        '--limit', scalar(@{$workers}) + 8,
        '--json', '--non-interactive', '--no-color',
    ], $stdout_path, $stderr_path);
    require_condition($exit_status == 0,
        'CUDA worker discovery command failed');
    my $result = load_json($stdout_path, 'CUDA worker discovery');
    require_condition($result->{ok}, 'CUDA worker discovery was unsuccessful');
    require_condition(ref($result->{root}) eq 'HASH',
        'CUDA worker discovery root is malformed');
    require_condition($result->{root}{pid} == $root_pid,
        'CUDA worker discovery root PID mismatch');
    require_condition($result->{root}{process_start_time} == $root_start_time,
        'CUDA worker discovery root procfs start time mismatch');
    require_condition(!$result->{truncated},
        'CUDA worker discovery candidates were truncated');
    require_condition(ref($result->{candidates}) eq 'ARRAY',
        'CUDA worker discovery candidates are malformed');
    my %discovered;
    for my $candidate (@{$result->{candidates}}) {
        next unless ref($candidate) eq 'HASH'
            && ref($candidate->{target}) eq 'HASH';
        $discovered{"$candidate->{target}{pid}:$candidate->{target}{process_start_time}"} = 1;
    }
    for my $worker (@{$workers}) {
        require_condition(
            $discovered{"$worker->{pid}:$worker->{process_start_time}"},
            'CUDA worker discovery did not return every launched worker identity');
        verify_identity($worker, 'after CUDA discovery');
    }
    return {
        exit_status => $exit_status,
        root         => {
            pid                => $root_pid,
            process_start_time => $root_start_time,
        },
        candidates   => $result->{candidates},
        files        => {
            stdout => artifact($stdout_path),
            stderr => artifact($stderr_path),
        },
    };
}

sub compile_fixture {
    my ($workspace, $build_dir) = @_;
    my $cuda_root = '/usr/local/cuda';
    my $agent = "$build_dir/libxprobe-cupti.so";
    my $fixture = "$build_dir/xprobe-cuda-multiprocess-worker";
    my $capabilities = capture_checked('GPU compute-capability query',
        'nvidia-smi', '--query-gpu=compute_cap', '--format=csv,noheader');
    my ($capability) = grep { length($_) } split /\n/, $capabilities;
    require_condition(defined($capability), 'GPU compute-capability query returned no rows');
    $capability =~ s/^\s+|\s+$//g;
    require_condition($capability =~ /^\d+\.\d+$/,
        "invalid GPU compute capability $capability");
    (my $architecture = $capability) =~ s/\.//g;
    run_checked('CUPTI Agent compilation',
        'gcc',
        '-std=c11', '-D_GNU_SOURCE', '-DXPROBE_HAS_CUPTI=1',
        '-fPIC', '-shared', '-pthread', '-O2',
        '-Wall', '-Wextra', '-Wpedantic', '-Werror',
        '-I/workspace/cupti/include', '-isystem', "$cuda_root/include",
        "$workspace/cupti/src/cupti_agent.c",
        "-L$cuda_root/lib64", "-Wl,-rpath,$cuda_root/lib64", '-lcupti',
        '-o', $agent);
    run_checked('CUDA worker compilation',
        'nvcc',
        '-std=c++17', '-O2',
        "-gencode=arch=compute_$architecture,code=sm_$architecture",
        "$workspace/benchmarks/cuda-multiprocess/cuda_multiprocess_worker.cu",
        '-o', $fixture);
    return ($agent, $fixture);
}

sub wait_for_concurrent_commands {
    my ($entries, $description) = @_;
    my $deadline = monotonic_ns() + (COMMAND_TIMEOUT_MS + 5_000) * 1_000_000;
    my %pending = map { $_->{ordinal} => $_ } @{$entries};
    while (%pending) {
        for my $ordinal (keys %pending) {
            my $entry = $pending{$ordinal};
            my $result = waitpid($entry->{command_pid}, WNOHANG);
            next if $result == 0;
            fail("waitpid failed for $description worker $ordinal: $!")
                if $result < 0;
            $entry->{finished_monotonic_ns} = monotonic_ns();
            $entry->{exit_status} = decode_wait_status($?);
            delete $pending{$ordinal};
        }
        if (%pending && monotonic_ns() >= $deadline) {
            for my $entry (values %pending) {
                kill 'KILL', $entry->{command_pid};
                waitpid($entry->{command_pid}, 0);
                $entry->{finished_monotonic_ns} = monotonic_ns();
                $entry->{exit_status} = decode_wait_status($?);
            }
            fail("per-worker $description commands exceeded the benchmark deadline");
        }
        usleep(5_000) if %pending;
    }
}

sub run_batch_body {
    my ($output_dir, $xprobe, $agent, $fixture, $worker_count,
        $workers, $worker_reports) = @_;
    my $batch_dir = "$output_dir/workers-$worker_count";
    mkdir $batch_dir or fail("unable to create $batch_dir: $!");
    for my $ordinal (0 .. $worker_count - 1) {
        push @{$workers}, make_worker($batch_dir, $ordinal, $fixture);
    }
    wait_for_workers_ready($batch_dir, $workers);
    my $discovery = discover_workers($batch_dir, $xprobe, $workers);
    my %baselines;
    for my $worker (@{$workers}) {
        verify_identity($worker, 'before baseline');
        $baselines{$worker->{ordinal}} =
            sample_iterations($worker, BASELINE_SECONDS);
    }

    my $representative = $workers->[0];
    my $broad_validate_stdout =
        worker_path($batch_dir, $representative, 'broad-validate.json');
    my $broad_validate_stderr =
        worker_path($batch_dir, $representative, 'broad-validate.stderr');
    my $broad_validate_exit = run_command([
        $xprobe, 'validate',
        '--pid', $representative->{pid},
        '--from', 'cuda:kernel_start',
        '--to', 'cuda:kernel_end',
        '--match', 'exact',
        '--json', '--non-interactive', '--no-color',
    ], $broad_validate_stdout, $broad_validate_stderr);
    require_condition($broad_validate_exit == 0,
        'representative broad selector validation command failed');
    my $broad_validation = validate_result(
        load_json($broad_validate_stdout, 'broad selector validation'),
        $representative, 'cuda:kernel_start', 'cuda:kernel_end');
    $broad_validation->{exit_status} = $broad_validate_exit;
    verify_identity($representative, 'after broad selector validation');

    my $inventory_stdout =
        worker_path($batch_dir, $representative, 'inventory.json');
    my $inventory_stderr =
        worker_path($batch_dir, $representative, 'inventory.stderr');
    my $inventory_before = iteration_snapshot($representative);
    my $inventory_started = monotonic_ns();
    my $inventory_exit = run_command(command_for_aggregate(
        $xprobe, $agent, $representative,
        'cuda:kernel_start', 'cuda:kernel_end', INVENTORY_DURATION_MS),
        $inventory_stdout, $inventory_stderr);
    my $inventory_finished = monotonic_ns();
    my $inventory_after = iteration_snapshot($representative);
    require_condition($inventory_exit == 0,
        'representative aggregate inventory command failed');
    verify_identity($representative, 'after aggregate inventory');
    my $inventory = load_json($inventory_stdout, 'aggregate inventory');
    require_condition($inventory->{ok} && $inventory->{status} eq 'completed',
        'aggregate inventory is not complete');
    my $inventory_collection = $inventory->{collection};
    require_condition(ref($inventory_collection) eq 'HASH',
        'aggregate inventory collection is malformed');
    require_condition($inventory_collection->{completeness} eq 'complete',
        'aggregate inventory is incomplete');
    require_condition($inventory_collection->{dropped_activities} == 0,
        'aggregate inventory dropped activities');
    require_condition(
        $inventory_collection->{observed_activities}
            == $inventory_collection->{grouped_activities},
        'aggregate inventory grouped activity count is inconsistent');
    require_condition(ref($inventory->{inventory}) eq 'HASH'
        && ref($inventory->{inventory}{groups}) eq 'ARRAY'
        && @{$inventory->{inventory}{groups}} == 1,
        'homogeneous aggregate inventory did not return exactly one group');
    my $group = $inventory->{inventory}{groups}[0];
    require_condition(ref($group) eq 'HASH' && $group->{activity} eq 'kernel',
        'inventory group is not a kernel');
    require_condition(defined($group->{name})
        && index($group->{name}, 'xprobe_multiprocess_stable_kernel') >= 0,
        'inventory did not identify the stable worker kernel');
    require_condition($group->{count} > 0,
        'inventory kernel group has no activities');
    my $start_selector = $group->{start_selector_hint};
    my $end_selector = $group->{end_selector_hint};
    require_condition(defined($start_selector)
        && index($start_selector, 'name~') >= 0,
        'inventory did not provide a narrow kernel start selector');
    require_condition(defined($end_selector)
        && index($end_selector, 'name~') >= 0,
        'inventory did not provide a narrow kernel end selector');
    require_condition(warning_present($inventory, 'CUPTI_AGENT_INJECTED'),
        'aggregate inventory omitted the required injection warning');

    my @validation_commands;
    for my $worker (@{$workers}) {
        verify_identity($worker, 'before selector validation');
        my $stdout_path = worker_path($batch_dir, $worker, 'validate.json');
        my $stderr_path = worker_path($batch_dir, $worker, 'validate.stderr');
        $worker->{files}{validate_stdout} = $stdout_path;
        $worker->{files}{validate_stderr} = $stderr_path;
        my $started = monotonic_ns();
        my $command_pid = launch_command([
            $xprobe, 'validate',
            '--pid', $worker->{pid},
            '--from', $start_selector,
            '--to', $end_selector,
            '--match', 'exact',
            '--json', '--non-interactive', '--no-color',
        ], $stdout_path, $stderr_path);
        push @validation_commands, {
            ordinal             => $worker->{ordinal},
            worker              => $worker,
            command_pid         => $command_pid,
            started_monotonic_ns => $started,
        };
    }
    wait_for_concurrent_commands(\@validation_commands, 'selector validation');
    my %validations;
    for my $entry (@validation_commands) {
        my $worker = $entry->{worker};
        require_condition($entry->{exit_status} == 0,
            "worker $worker->{ordinal} selector validation command failed");
        my $validation = validate_result(
            load_json($worker->{files}{validate_stdout}, 'selector validation'),
            $worker, $start_selector, $end_selector);
        $validation->{exit_status} = $entry->{exit_status};
        $validation->{started_monotonic_ns} =
            $entry->{started_monotonic_ns};
        $validation->{finished_monotonic_ns} =
            $entry->{finished_monotonic_ns};
        $validations{$worker->{ordinal}} = $validation;
        verify_identity($worker, 'after selector validation');
    }

    my @measure_commands;
    for my $worker (@{$workers}) {
        verify_identity($worker, 'before exact measurement');
        my $spec = worker_path($batch_dir, $worker, 'measurement-spec.json');
        my $stdout_path = worker_path($batch_dir, $worker, 'measure.json');
        my $stderr_path = worker_path($batch_dir, $worker, 'measure.stderr');
        my $events = worker_path($batch_dir, $worker, 'events.jsonl');
        write_measurement_spec($spec, $worker, $start_selector, $end_selector);
        $worker->{files}{spec} = $spec;
        $worker->{files}{measure_stdout} = $stdout_path;
        $worker->{files}{measure_stderr} = $stderr_path;
        $worker->{files}{events} = $events;
        my $started = monotonic_ns();
        my $command_pid = launch_command(
            command_for_spec_measure($xprobe, $agent, $spec, $events),
            $stdout_path, $stderr_path);
        push @measure_commands, {
            ordinal              => $worker->{ordinal},
            worker               => $worker,
            command_pid          => $command_pid,
            started_monotonic_ns => $started,
        };
    }
    usleep(COLLECTION_WARMUP_US);
    my $collection_sample_started_ns = monotonic_ns();
    for my $entry (@measure_commands) {
        $entry->{collection_start} = iteration_snapshot($entry->{worker});
    }
    usleep(COLLECTION_SAMPLE_US);
    for my $entry (@measure_commands) {
        $entry->{collection_end} = iteration_snapshot($entry->{worker});
    }
    my $collection_sample_finished_ns = monotonic_ns();
    my $collection_sample_wall_ns =
        $collection_sample_finished_ns - $collection_sample_started_ns;
    wait_for_concurrent_commands(\@measure_commands, 'measure');
    my $latest_start = 0;
    my $earliest_finish;
    for my $entry (@measure_commands) {
        $latest_start = $entry->{started_monotonic_ns}
            if $entry->{started_monotonic_ns} > $latest_start;
        $earliest_finish = $entry->{finished_monotonic_ns}
            if !defined($earliest_finish)
            || $entry->{finished_monotonic_ns} < $earliest_finish;
    }
    require_condition($latest_start < $earliest_finish,
        'per-worker measure command windows did not overlap');

    my @all_paths = (
        $discovery->{files}{stdout}{path},
        $discovery->{files}{stderr}{path},
        $broad_validate_stdout,
        $broad_validate_stderr,
        $inventory_stdout,
        $inventory_stderr,
    );
    for my $entry (@measure_commands) {
        my $worker = $entry->{worker};
        my $collection_end = $entry->{collection_end};
        require_condition($collection_end >= $entry->{collection_start},
            'worker iteration counter moved backwards during measure');
        require_condition($entry->{exit_status} == 0,
            "worker $worker->{ordinal} exact measurement command failed");
        verify_identity($worker, 'after exact measurement');
        my $exact = load_json($worker->{files}{measure_stdout},
            'exact measurement');
        my $quality = validate_exact_result($exact, $worker);
        my $injection_warning =
            warning_present($exact, 'CUPTI_AGENT_INJECTED');
        require_condition($injection_warning,
            'measure omitted required injection warning')
            if $validations{$worker->{ordinal}}{agent_activation}
                eq 'injection_required';
        my $wall_ns =
            $entry->{finished_monotonic_ns} - $entry->{started_monotonic_ns};
        my $collection_delta =
            $collection_end - $entry->{collection_start};
        my %files = (
            worker_stdout => artifact($worker->{stdout_path}),
            worker_stderr => artifact($worker->{stderr_path}),
        );
        for my $key (keys %{$worker->{files}}) {
            $files{$key} = artifact($worker->{files}{$key});
        }
        push @{$worker_reports}, {
            ordinal             => $worker->{ordinal},
            target              => {
                pid                => $worker->{pid},
                process_start_time => $worker->{process_start_time},
            },
            fixture_exit_status => undef,
            startup             => {
                launched_monotonic_ns => $worker->{launched_monotonic_ns},
                ready_monotonic_ns    => $worker->{ready_monotonic_ns},
                wall_ns => $worker->{ready_monotonic_ns}
                    - $worker->{launched_monotonic_ns},
            },
            baseline_iterations => $baselines{$worker->{ordinal}},
            collection_iterations => {
                start => $entry->{collection_start},
                end   => $collection_end,
                delta => $collection_delta,
                wall_ns => $collection_sample_wall_ns,
                iterations_per_second =>
                    $collection_delta * 1_000_000_000
                    / $collection_sample_wall_ns,
                retained_events_per_second =>
                    $quality->{cuda_events} * 1_000_000_000 / $wall_ns,
            },
            perturbation => {
                baseline_iterations_per_second =>
                    $baselines{$worker->{ordinal}}{iterations_per_second},
                collection_iterations_per_second =>
                    $collection_delta * 1_000_000_000
                    / $collection_sample_wall_ns,
                relative_change =>
                    ($collection_delta * 1_000_000_000
                        / $collection_sample_wall_ns)
                    / $baselines{$worker->{ordinal}}{iterations_per_second}
                    - 1.0,
            },
            command => {
                exit_status          => $entry->{exit_status},
                started_monotonic_ns => $entry->{started_monotonic_ns},
                finished_monotonic_ns => $entry->{finished_monotonic_ns},
                wall_ns              => $wall_ns,
            },
            validation        => $validations{$worker->{ordinal}},
            injection_warning => $injection_warning,
            quality           => $quality,
            files             => \%files,
        };
        push @all_paths, $worker->{stdout_path}, $worker->{stderr_path};
        push @all_paths, values %{$worker->{files}};
    }
    my %unique_paths = map { $_ => 1 } @all_paths;
    require_condition(@all_paths == keys(%unique_paths),
        'benchmark artifact path reuse detected');
    my $inventory_wall_ns = $inventory_finished - $inventory_started;
    return {
        workers        => $worker_count,
        representative => {
            pid                => $representative->{pid},
            process_start_time => $representative->{process_start_time},
        },
        discovery      => $discovery,
        selectors      => {
            from => $start_selector,
            to   => $end_selector,
        },
        aggregate_inventory => {
            broad_validation => {
                %{$broad_validation},
                files => {
                    stdout => artifact($broad_validate_stdout),
                    stderr => artifact($broad_validate_stderr),
                },
            },
            command => {
                exit_status           => $inventory_exit,
                started_monotonic_ns  => $inventory_started,
                finished_monotonic_ns => $inventory_finished,
                wall_ns               => $inventory_wall_ns,
            },
            collection_iterations => {
                start => $inventory_before,
                end   => $inventory_after,
                delta => $inventory_after - $inventory_before,
                iterations_per_second =>
                    ($inventory_after - $inventory_before)
                    * 1_000_000_000 / $inventory_wall_ns,
            },
            injection_warning => JSON::PP::true,
            collection        => $inventory_collection,
            group             => $group,
            files             => {
                stdout => artifact($inventory_stdout),
                stderr => artifact($inventory_stderr),
            },
        },
        measure_windows_overlap => JSON::PP::true,
        workers_report          => $worker_reports,
    };
}

sub run_batch {
    my ($output_dir, $xprobe, $agent, $fixture, $worker_count) = @_;
    my @workers;
    my @worker_reports;
    my ($result, $primary_error, $cleanup_error);
    eval {
        $result = run_batch_body(
            $output_dir, $xprobe, $agent, $fixture, $worker_count,
            \@workers, \@worker_reports);
        1;
    } or $primary_error = $@ || 'unknown benchmark failure';
    eval {
        stop_workers(\@workers);
        for my $report (@worker_reports) {
            my $worker = $workers[$report->{ordinal}];
            require_condition(defined($worker->{exit_status}),
                "worker $report->{ordinal} fixture did not produce an exit status");
            $report->{fixture_exit_status} = $worker->{exit_status};
        }
        1;
    } or $cleanup_error = $@ || 'unknown cleanup failure';
    if ($primary_error) {
        chomp $primary_error;
        if ($cleanup_error) {
            chomp $cleanup_error;
            fail("$primary_error; cleanup failed: $cleanup_error");
        }
        fail($primary_error);
    }
    fail($cleanup_error) if $cleanup_error;
    return $result;
}

sub main {
    require_condition(@ARGV == 1,
        'usage: run-container.pl <output-directory>');
    my $output_dir = $ARGV[0];
    $OUTPUT_DIRECTORY = $output_dir;
    mkdir $output_dir unless -d $output_dir;
    require_condition(-d $output_dir,
        "output directory is unavailable at $output_dir");
    my $workspace = '/workspace';
    my $xprobe = "$workspace/target/debug/xprobe";
    require_condition(-f $xprobe, "xprobe binary is missing at $xprobe");
    my $build_dir = '/tmp/xprobe-cuda-multiprocess';
    mkdir $build_dir unless -d $build_dir;
    require_condition(-d $build_dir,
        "build directory is unavailable at $build_dir");
    my ($agent, $fixture) = compile_fixture($workspace, $build_dir);
    my $gpu_rows = capture_checked('GPU information query',
        'nvidia-smi',
        '--query-gpu=name,driver_version,compute_cap',
        '--format=csv,noheader');
    my ($gpu) = grep { length($_) } split /\n/, $gpu_rows;
    require_condition(defined($gpu), 'GPU information query returned no rows');
    $gpu =~ s/^\s+|\s+$//g;
    my @batches;
    for my $count (1, 2, 4) {
        push @batches, run_batch(
            $output_dir, $xprobe, $agent, $fixture, $count);
    }
    write_json("$output_dir/report.json", {
        schema_version => '2.0',
        ok             => JSON::PP::true,
        gpu            => $gpu,
        batches        => \@batches,
    });
}

eval { main(); 1 } or do {
    my $error = $@ || 'unknown failure';
    chomp $error;
    print STDERR "cuda multiprocess benchmark failed: $error\n";
    exit 1;
};
