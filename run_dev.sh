#!/bin/bash
# =============================================================================
# SNode.C SSO/MFA Development Script
# Builds the project and runs both IdP and Protected WebApp services
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
IDP_BIN="$BUILD_DIR/src/apps/auth_idp/auth_idp"
WEBAPP_BIN="$BUILD_DIR/src/apps/protected_webapp/protected_webapp"

# Ports used by our services
IDP_PORT=8083
WEBAPP_PORT=8055

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

# Kill any process using specified port
kill_port() {
    local port=$1
    local pid=$(lsof -ti :$port 2>/dev/null)
    if [ -n "$pid" ]; then
        echo -e "${YELLOW}Killing process on port $port (PID: $pid)${NC}"
        kill -9 $pid 2>/dev/null || true
    fi
}

# Stop all our services
stop_services() {
    echo -e "${YELLOW}Stopping any existing services...${NC}"
    
    # Kill by port
    kill_port $IDP_PORT
    kill_port $WEBAPP_PORT
    
    # Also kill by process name as backup
    pkill -9 -f "auth_idp" 2>/dev/null || true
    pkill -9 -f "protected_webapp" 2>/dev/null || true
    
    sleep 1
    echo -e "${GREEN}Services stopped.${NC}"
}

cleanup() {
    echo ""
    stop_services
    exit 0
}

trap cleanup SIGINT SIGTERM

# --- Parse arguments ---
BUILD_ONLY=false
RUN_ONLY=false
WITH_LEAKS=false
WITH_VALGRIND=false
CLEAN_BUILD=false
STOP_ONLY=false

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --build-only     Only build, don't run services"
    echo "  --run-only       Skip build, just run services"
    echo "  --with-leaks     Run with macOS leaks tool (memory leak detection)"
    echo "  --with-valgrind  Run with Valgrind (if installed, better for Linux)"
    echo "  --clean          Clean build directory before building"
    echo "  --stop           Stop all running services and exit"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Login Credentials:"
    echo "  User with MFA:    testuser / password"
    echo "  User without MFA: normaluser / password"
    echo "  Admin with MFA:   admin / admin123"
}

for arg in "$@"; do
    case $arg in
        --build-only) BUILD_ONLY=true ;;
        --run-only) RUN_ONLY=true ;;
        --with-leaks) WITH_LEAKS=true ;;
        --with-valgrind) WITH_VALGRIND=true ;;
        --clean) CLEAN_BUILD=true ;;
        --stop) STOP_ONLY=true ;;
        -h|--help) show_help; exit 0 ;;
    esac
done

# --- Stop only mode ---
if [[ "$STOP_ONLY" == true ]]; then
    stop_services
    exit 0
fi

# --- Clean if requested ---
if [[ "$CLEAN_BUILD" == true ]]; then
    print_header "Cleaning build directory"
    rm -rf "$BUILD_DIR"
    echo -e "${GREEN}Build directory cleaned.${NC}"
fi

# --- Build ---
if [[ "$RUN_ONLY" == false ]]; then
    print_header "Configuring with CMake"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake ..

    print_header "Building project"
    cmake --build . -j$(sysctl -n hw.ncpu)

    echo -e "${GREEN}Build complete!${NC}"
fi

if [[ "$BUILD_ONLY" == true ]]; then
    echo -e "${GREEN}Build-only mode. Exiting.${NC}"
    exit 0
fi

# --- ALWAYS kill any existing instances before starting ---
print_header "Checking for existing services"
stop_services

# --- Run services ---
print_header "Starting Services"

cd "$BUILD_DIR"

if [[ "$WITH_VALGRIND" == true ]]; then
    # Check if valgrind is installed
    if ! command -v valgrind &> /dev/null; then
        echo -e "${RED}Valgrind not found! Install with: brew install valgrind${NC}"
        echo -e "${YELLOW}Note: Valgrind has limited macOS support. Consider --with-leaks instead.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Running with Valgrind memory leak detection${NC}"
    echo -e "${YELLOW}This will be slower but provides detailed leak reports.${NC}"
    
    # Start IdP with valgrind
    echo -e "${GREEN}Starting IdP Server with Valgrind on port $IDP_PORT...${NC}"
    cd "$BUILD_DIR/src/apps/auth_idp"
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
        --log-file="$BUILD_DIR/valgrind_auth_idp.log" \
        ./auth_idp &
    IDP_PID=$!
    
    # Start WebApp with valgrind
    echo -e "${GREEN}Starting Protected WebApp with Valgrind on port $WEBAPP_PORT...${NC}"
    cd "$BUILD_DIR/src/apps/protected_webapp"
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
        --log-file="$BUILD_DIR/valgrind_protected_webapp.log" \
        ./protected_webapp &
    WEBAPP_PID=$!
    
    echo ""
    echo -e "${YELLOW}Valgrind logs will be written to:${NC}"
    echo -e "  $BUILD_DIR/valgrind_auth_idp.log"
    echo -e "  $BUILD_DIR/valgrind_protected_webapp.log"

elif [[ "$WITH_LEAKS" == true ]]; then
    echo -e "${YELLOW}Running with macOS leaks tool (memory leak detection)${NC}"
    echo -e "${YELLOW}Leak report will be generated when services exit.${NC}"
    
    # Start IdP with leaks
    echo -e "${GREEN}Starting IdP Server with leak detection on port $IDP_PORT...${NC}"
    cd "$BUILD_DIR/src/apps/auth_idp"
    leaks --atExit -- ./auth_idp &
    IDP_PID=$!
    
    # Start WebApp with leaks
    echo -e "${GREEN}Starting Protected WebApp with leak detection on port $WEBAPP_PORT...${NC}"
    cd "$BUILD_DIR/src/apps/protected_webapp"
    leaks --atExit -- ./protected_webapp &
    WEBAPP_PID=$!

else
    # Normal mode
    echo -e "${GREEN}Starting IdP Server on port $IDP_PORT...${NC}"
    cd "$BUILD_DIR/src/apps/auth_idp"
    ./auth_idp &
    IDP_PID=$!
    
    echo -e "${GREEN}Starting Protected WebApp on port $WEBAPP_PORT...${NC}"
    cd "$BUILD_DIR/src/apps/protected_webapp"
    ./protected_webapp &
    WEBAPP_PID=$!
fi

sleep 2

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Services are running!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BLUE}Protected WebApp:${NC}  http://localhost:$WEBAPP_PORT"
echo -e "  ${BLUE}IdP Server:${NC}        http://localhost:$IDP_PORT"
echo ""
echo -e "  ${YELLOW}Login Credentials:${NC}"
echo -e "    User with MFA:    ${GREEN}testuser${NC} / ${GREEN}password${NC}"
echo -e "    User without MFA: ${GREEN}normaluser${NC} / ${GREEN}password${NC}"
echo -e "    Admin with MFA:   ${GREEN}admin${NC} / ${GREEN}admin123${NC}"
echo ""
if [[ "$WITH_VALGRIND" == true ]]; then
    echo -e "  ${YELLOW}Valgrind mode active - check logs in build/ after exit${NC}"
fi
echo -e "  Press ${RED}Ctrl+C${NC} to stop all services."
echo ""

# Wait for processes
wait $IDP_PID $WEBAPP_PID
