#!/bin/bash
# Usage: sudo tests/run_tests.sh            (safe tests)
#        sudo WITH_FORKBOMB=1 tests/run_tests.sh   (adds the fork bomb; needs cgroups v2, use a VM!)
cd "$(dirname "$0")/.." || exit 1
T=tests; I=$T/input.txt; S=$T/expected_sum.txt
ARGS=( $T/ac.c $I $S  $T/wa.c $I $S  $T/tle.c $I $S  $T/sleeper.c $I $S
       $T/mle.c $I $S $T/ole.c $I $S  $T/re.c $I $S   $T/ce.c $I $S
       $T/fs.c $I $T/expected_blocked.txt )
[ "$WITH_FORKBOMB" = "1" ] && ARGS+=( $T/forkbomb.c $I $S )
./securerun -t 2 -m 64 -j 4 "${ARGS[@]}"
