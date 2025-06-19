#!/bin/bash

# OWASP ZAP Management Script
# This script helps manage ZAP proxy for DAST testing

set -e

# Configuration
ZAP_PORT=${ZAP_PORT:-8080}
ZAP_HOST=${ZAP_HOST:-localhost}
ZAP_MEMORY=${ZAP_MEMORY:-1024m}
REPORTS_DIR="reports"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_zap_installed() {
    if ! command -v zap.sh &> /dev/null && ! command -v owasp-zap &> /dev/null; then
        log_error "OWASP ZAP is not installed or not in PATH"
        log_info "Please install ZAP from: https://www.zaproxy.org/download/"
        log_info "Or using Docker: docker pull zaproxy/zap-stable"
        exit 1
    fi
}

check_docker_available() {
    if ! command -v docker &> /dev/null; then
        log_warning "Docker is not available. Will try to use local ZAP installation."
        return 1
    fi
    return 0
}

start_zap_daemon() {
    log_info "Starting ZAP daemon on port $ZAP_PORT..."
    
    if check_docker_available; then
        log_info "Using Docker to run ZAP..."
        
        # Check if ZAP container is already running
        if docker ps --format 'table {{.Names}}' | grep -q "zap-daemon"; then
            log_warning "ZAP daemon container is already running"
            # Check if it's running on the correct port
            container_port=$(docker port zap-daemon 2>/dev/null | grep "$ZAP_PORT" || echo "")
            if [ -n "$container_port" ]; then
                log_info "Container is running on the correct port $ZAP_PORT"
                return 0
            else
                log_warning "Container is running on a different port. Stopping and restarting..."
                docker stop zap-daemon >/dev/null 2>&1 || true
                docker rm zap-daemon >/dev/null 2>&1 || true
            fi
        else
            # Check if container exists but is stopped
            if docker ps -a --format 'table {{.Names}}' | grep -q "zap-daemon"; then
                log_info "Removing existing stopped ZAP container..."
                docker rm zap-daemon >/dev/null 2>&1 || true
            fi
        fi
        
        # Start ZAP in daemon mode using Docker
        docker run -d \
            --name zap-daemon \
            -p $ZAP_PORT:$ZAP_PORT \
            -v "$(pwd)/$REPORTS_DIR:/zap/wrk" \
            zaproxy/zap-stable \
            zap.sh -daemon -host 0.0.0.0 -port $ZAP_PORT -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true
            
        log_success "ZAP daemon started in Docker container"
    else
        # Use local ZAP installation
        check_zap_installed
        
        # Check if ZAP is already running
        if lsof -Pi :$ZAP_PORT -sTCP:LISTEN -t >/dev/null ; then
            log_warning "Port $ZAP_PORT is already in use. ZAP might be already running."
            return 0
        fi
        
        # Start ZAP daemon
        if command -v zap.sh &> /dev/null; then
            nohup zap.sh -daemon -host $ZAP_HOST -port $ZAP_PORT -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true > zap.log 2>&1 &
        else
            nohup owasp-zap -daemon -host $ZAP_HOST -port $ZAP_PORT -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true > zap.log 2>&1 &
        fi
        
        log_success "ZAP daemon started locally"
    fi
    
    # Wait for ZAP to be ready
    log_info "Waiting for ZAP to be ready..."
    for i in {1..60}; do
        if curl -s "http://$ZAP_HOST:$ZAP_PORT/" >/dev/null 2>&1; then
            log_success "ZAP is ready!"
            return 0
        fi
        sleep 2
    done
    
    log_error "ZAP failed to start or is not responding"
    return 1
}

stop_zap_daemon() {
    log_info "Stopping ZAP daemon..."
    
    if check_docker_available && docker ps --format 'table {{.Names}}' | grep -q "zap-daemon"; then
        docker stop zap-daemon >/dev/null 2>&1 || true
        docker rm zap-daemon >/dev/null 2>&1 || true
        log_success "ZAP Docker container stopped and removed"
    else
        # Stop local ZAP process
        if lsof -Pi :$ZAP_PORT -sTCP:LISTEN -t >/dev/null ; then
            pkill -f "zap.sh.*daemon" || true
            pkill -f "owasp-zap.*daemon" || true
            log_success "ZAP daemon stopped"
        else
            log_warning "ZAP daemon is not running"
        fi
    fi
}

ensure_zap_daemon_running() {
    log_info "Ensuring ZAP daemon is running..."
    
    # Check if ZAP daemon is accessible
    if curl -s "http://$ZAP_HOST:$ZAP_PORT/" >/dev/null 2>&1; then
        log_success "ZAP daemon is already running and accessible on port $ZAP_PORT"
        return 0
    fi
    
    # If not accessible, try to start it
    log_info "ZAP daemon not accessible. Starting it..."
    start_zap_daemon
}

run_scan_via_daemon() {
    local target_url=$1
    local scan_type=${2:-"baseline"}
    
    if [ -z "$target_url" ]; then
        log_error "Target URL is required for scan"
        return 1
    fi
    
    log_info "Running ZAP $scan_type scan against $target_url via daemon..."
    
    # Ensure daemon is running
    ensure_zap_daemon_running
    
    # Create reports directory
    mkdir -p $REPORTS_DIR
    
    # Use the Python script to run the scan through the daemon
    case "$scan_type" in
        "baseline"|"api")
            python test_zap_dast.py --target "$target_url" --zap-port "$ZAP_PORT"
            ;;
        "full")
            # For full scans, we can use the same Python script but with different parameters
            # or extend the Python script to support full scan mode
            python test_zap_dast.py --target "$target_url" --zap-port "$ZAP_PORT"
            ;;
        *)
            log_error "Unknown scan type: $scan_type"
            return 1
            ;;
    esac
    
    log_success "$scan_type scan completed. Reports saved in $REPORTS_DIR/"
}

run_baseline_scan() {
    local target_url=$1
    run_scan_via_daemon "$target_url" "baseline"
}

run_full_scan() {
    local target_url=$1
    run_scan_via_daemon "$target_url" "full"
}

run_api_scan() {
    local target_url=${1:-"http://localhost:8000"}
    run_scan_via_daemon "$target_url" "api"
}

show_status() {
    log_info "ZAP Status Check"
    echo "=================="
    
    if curl -s "http://$ZAP_HOST:$ZAP_PORT/" >/dev/null 2>&1; then
        version=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/" | python -c "import sys, json; print(json.load(sys.stdin)['version'])" 2>/dev/null || echo "Unknown")
        log_success "ZAP is running on port $ZAP_PORT (Version: $version)"
        
        # Show sites in ZAP
        sites=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/core/view/sites/" 2>/dev/null)
        if [ "$sites" != '{"sites":[]}' ]; then
            log_info "Sites in ZAP session:"
            echo "$sites" | python -c "import sys, json; [print(f'  - {site}') for site in json.load(sys.stdin)['sites']]" 2>/dev/null || echo "  (Could not parse sites)"
        fi
    else
        log_warning "ZAP is not running or not accessible on port $ZAP_PORT"
    fi
    
    # Check for Docker
    if check_docker_available; then
        if docker ps --format 'table {{.Names}}' | grep -q "zap-daemon"; then
            log_info "ZAP Docker container is running"
        fi
    fi
}

show_help() {
    echo "OWASP ZAP Management Script"
    echo "==========================="
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start               Start ZAP daemon"
    echo "  stop                Stop ZAP daemon"
    echo "  status              Show ZAP status"
    echo "  baseline [URL]      Run baseline scan (default: http://localhost:8000)"
    echo "  fullscan [URL]      Run full scan (default: http://localhost:8000)"
    echo "  apiscan [URL]       Run API DAST scan (default: http://localhost:8000)"
    echo "  help                Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  ZAP_PORT           ZAP proxy port (default: 8080)"
    echo "  ZAP_HOST           ZAP host (default: localhost)"
    echo "  ZAP_MEMORY         ZAP memory allocation (default: 1024m)"
    echo ""
    echo "Examples:"
    echo "  $0 start"
    echo "  $0 apiscan http://localhost:8000"
    echo "  $0 baseline http://example.com"
    echo "  $0 stop"
}

# Main script logic
case "${1:-help}" in
    start)
        start_zap_daemon
        ;;
    stop)
        stop_zap_daemon
        ;;
    status)
        show_status
        ;;
    baseline)
        run_baseline_scan "${2:-http://localhost:8000}"
        ;;
    fullscan)
        run_full_scan "${2:-http://localhost:8000}"
        ;;
    apiscan)
        run_api_scan "${2:-http://localhost:8000}"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
