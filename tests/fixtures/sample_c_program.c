// tests/fixtures/sample_c_program.c
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[]) {
    // Read config file
    FILE *config = fopen("/etc/myapp/config.ini", "r");
    fclose(config);

    // Write PID file
    FILE *pid = fopen("/var/run/myapp.pid", "w");
    fprintf(pid, "%d\n", getpid());
    fclose(pid);

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    // Bind to port
    struct sockaddr_in addr;
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    return 0;
}
