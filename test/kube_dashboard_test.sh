sed -ri "s|'(deepnetwork/scanners:).+'|'\1${CIRCLE_SHA1}'|" ./deploy/dashboard.yaml


function check_scanners_are_ready() {
    local timeout_epoch
    timeout_epoch=$(date -d "+2 minutes" +%s)
    echo "Waiting for scanners to be ready"
    while ! kubectl get pods | grep -E "scanners.*1/1.*Running"; do
        check_timeout "${timeout_epoch}"
        echo -n "."
    done

    echo "Scanners are running!"
}

function check_timeout() {
    local timeout_epoch="${1}"
    if [[ "$(date +%s)" -ge "${timeout_epoch}" ]]; then
        echo -e "Timeout hit waiting for readiness: exiting"
        grab_logs
        clean_up
        exit 1
    fi
}

kubectl apply -f ./deploy/dashboard.yaml &>/dev/null

check_dashboard_is_ready

kubectl port-forward svc/scanners 3000:80 &
sleep 30
curl -f http://localhost:3000 > /dev/null
curl -f http://localhost:3000/health > /dev/null
curl -f http://localhost:3000/results.json > /dev/null
curl -f http://localhost:3000/details/security > /dev/null
