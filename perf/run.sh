#!/bin/bash

commands=(
    "curl -w '%{time_total}\n' -o /dev/null -s -X GET https://localhost:4445 --insecure --http1.1"
    "curl -w '%{time_total}\n' -o /dev/null -s -X POST https://localhost:4445 --insecure --http1.1"
    "curl -w '%{time_total}\n' -o /dev/null -s -X PUT https://localhost:4445 --insecure --http1.1"
    "curl -w '%{time_total}\n' -o /dev/null -s -X PATCH https://localhost:4445 --insecure --http1.1"
    "curl -w '%{time_total}\n' -o /dev/null -s -X DELETE https://localhost:4445 --insecure --http1.1"
    "curl -w '%{time_total}\n' -o /dev/null -s -X CONNECT https://localhost:4445 --insecure --http1.1"
    "curl -w '%{time_total}\n' -o /dev/null -s -X OPTIONS https://localhost:4445 --insecure --http1.1"
    "curl -w '%{time_total}\n' -o /dev/null -s -X TRACE https://localhost:4445 --insecure --http1.1"
)

total_time=0
total_requests=0

for i in {1..10000}
do
    for cmd in "${commands[@]}"
    do
        response_time=$(eval "$cmd")
        total_time=$(echo "$total_time + $response_time" | bc)
        total_requests=$((total_requests + 1))
    done
done

average_time=$(echo "scale=4; $total_time / $total_requests" | bc)
echo "Average response time: $average_time seconds"
