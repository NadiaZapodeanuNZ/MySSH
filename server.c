#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define PORT 2607
#define MAX_BUFFER 2048
#define MAX_USERS 50
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"
#define USER_FILE "Users/users.txt"


pthread_mutex_t mutlock = PTHREAD_MUTEX_INITIALIZER;
const char *allowed_path = "/home/nzapo/MySSH/Files";


typedef struct {
    char username[50];
    char password[70];
    int auth;
    SSL *ssl;
} User;

typedef struct 
{
    int client_socket;
    SSL *ssl;
} ThreadArgs;

User users[MAX_USERS];

//----Saving data about users in file----------------
void save_users_to_file() 
{  
    printf("DEBUG: Saving users to file: %s\n", USER_FILE);
    FILE *file = fopen(USER_FILE, "w");
    if (file == NULL) 
    {
        perror("ERROR: Unable to open users file");
        return;
    }

    for (int i = 0; i < MAX_USERS; i++) 
    {
        if (users[i].username[0] != '\0') 
        {
            printf("DEBUG: Writing user %s to file\n", users[i].username);
            fprintf(file, "%s %s %d\n", users[i].username, users[i].password, users[i].auth);
        }
    }

    fclose(file);
   
    printf("DEBUG: Finished saving users\n");
}

//----Function to load users from file----------------
void load_users_from_file() 
{
    printf("DEBUG: Loading users from file: %s\n", USER_FILE);
    FILE *file = fopen(USER_FILE, "r");
    if (file == NULL) 
    {
        perror("ERROR: Unable to open users file");
        return;
    }

    char username[50], password[70];
    int auth;
    while (fscanf(file, "%49s %69s %d\n", username, password, &auth) == 3) 
    {
        for (int i = 0; i < MAX_USERS; i++) 
        {
            if (users[i].username[0] == '\0')
            {
                printf("DEBUG: Adding user %s with auth %d\n", username, auth);
                strncpy(users[i].username, username, sizeof(username) - 1);
                strncpy(users[i].password, password, sizeof(password) - 1);
                users[i].auth = 0;
                users[i].ssl = NULL;
                break;
            }
        }
    }

    fclose(file);
 
    printf("DEBUG: Finished loading users\n");
}
//---------------------update status users - auth can be 0 - not logged or 1 - logged in----------------
void update_user_status(char *username, int auth) 
{
    printf("DEBUG: Searching for user %s and updating auth status to %d\n", username, auth);
    
    FILE *file = fopen(USER_FILE, "r+");
    if (file == NULL) {
        perror("ERROR: Unable to open users file");
        return;
    }

    char line[MAX_BUFFER];
    long pos;
    int found = 0;

    while (fgets(line, sizeof(line), file)) {
        pos = ftell(file);
        char stored_username[50], stored_password[70];
        int stored_auth;

        if (sscanf(line, "%49s %69s %d", stored_username, stored_password, &stored_auth) == 3) 
        {

            if (strcmp(stored_username, username) == 0) {
                printf("DEBUG: Found user %s, updating auth status to %d\n", username, auth);
                fseek(file, pos - strlen(line), SEEK_SET);
                fprintf(file, "%s %s %d\n", stored_username, stored_password, auth);

                found = 1;
                break;
            }
        }
    }

    fclose(file);

    if (found) {
        printf("DEBUG: User %s status updated to %d\n", username, auth);
    } else {
        printf("DEBUG: User %s not found\n", username);
    }
}

//-------initializing users with empty fields-------------
void initialize_users() 
{
    for (int i = 0; i < MAX_USERS; i++) 
    {
        memset(users[i].username, 0, sizeof(users[i].username));
        memset(users[i].password, 0, sizeof(users[i].password));
        users[i].auth = 0;
        users[i].ssl = NULL;
    }
 
}

//--------crypting socket, session, etc--- SSL/TLS
void initialize_openssl() 
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}


SSL_CTX *create_context() 
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) 
    {
        perror("ERROR: Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) 
{
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}


void *handle_file_download(void *args) {
    SSL *ssl = (SSL *)((void **)args)[0];
    char *command = (char *)((void **)args)[1];
    char filename[MAX_BUFFER];
    char path_server[MAX_BUFFER];
    char path_pc[MAX_BUFFER];

    
    if (!is_logged_in(ssl)) {
        const char *error_message = "ERROR: You are not logged in! Please login first.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);  
        return NULL;
    }

    
    printf("DEBUG: Full command received: '%s'\n", command);
    int parsed = sscanf(command, "download:%20s path_server:%100s path_pc:%100s", filename, path_server, path_pc);
    printf("DEBUG: sscanf parsed: %d\n", parsed);
    printf("DEBUG: Parsed values - filename: '%s', path_server: '%s', path_pc: '%s'\n", 
            filename, path_server, path_pc);
    
    if (parsed != 3) {
        const char *error_message = "ERROR: Invalid download command format.\n Use: download:filename path_server:path_server_allowed path_pc:your_path_pc\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);  
        return NULL;
    }

    
    printf("DEBUG: Checking allowed path from server...\n");
    if (strcmp(path_server, allowed_path) != 0) {
        const char *error_message = "ERROR: Invalid server path! Only /home/nzapo/MySSH/Files is allowed.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        return NULL;
    }

    printf("Processing download request for file: %s\n", filename);

    
    pthread_mutex_lock(&mutlock);

    
    char full_path_server[MAX_BUFFER];
    snprintf(full_path_server, sizeof(full_path_server), "%s/%s", path_server, filename);

    
    FILE *source = fopen(full_path_server, "rb");
    if (!source) {
        pthread_mutex_unlock(&mutlock); // Unlock  if source file cannot be opened
        const char *error_message = "ERROR: Unable to open requested file.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        return NULL;
    }

    
    char full_path_pc[MAX_BUFFER];
    snprintf(full_path_pc, sizeof(full_path_pc), "%s/%s", path_pc, filename);

    if (access(path_pc, F_OK) == -1) 
    {
        printf("DEBUG: Directory '%s' does not exist. Unlocking mutex...\n", path_pc);
        fclose(source);
        pthread_mutex_unlock(&mutlock); // Unlock  if directory doesn't exist
        const char *error_message = "ERROR: Directory does not exist.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        return NULL;
    }

    
    if (access(full_path_pc, F_OK) == 0) 
    {
        const char *message = "File already exists. Do you want to overwrite it? (yes/no)\n";
        SSL_write(ssl, message, strlen(message));

        char response[MAX_BUFFER];
        SSL_read(ssl, response, sizeof(response) - 1);
        response[sizeof(response) - 1] = '\0';

        if (strcmp(response, "yes") == 0) 
        {
            FILE *dest = fopen(full_path_pc, "wb");
            if (!dest) {
                printf("DEBUG: Unable to open destination file '%s'. Unlocking mutex...\n", full_path_pc);
                fclose(source);
                pthread_mutex_unlock(&mutlock); 
                const char *error_message = "ERROR: Unable to open destination file.\n";
                SSL_write(ssl, error_message, strlen(error_message));
                free(command);
                return NULL;
            }

            
            char buffer[MAX_BUFFER];
            size_t bytes_read;
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), source)) > 0) {
                if (fwrite(buffer, 1, bytes_read, dest) != bytes_read) {
                    printf("DEBUG: Error writing to destination file. Unlocking mutex...\n");
                    fclose(source);
                    fclose(dest);
                    pthread_mutex_unlock(&mutlock); // Unlock if write failed
                    const char *error_message = "ERROR: Write error to destination file.\n";
                    SSL_write(ssl, error_message, strlen(error_message));
                    free(command);
                    return NULL;
                }
                fflush(dest);
            }
            fclose(dest);
        } else 
        {
            fclose(source);
            pthread_mutex_unlock(&mutlock);
            const char *error_message = "ERROR: File not overwritten.\n";
            SSL_write(ssl, error_message, strlen(error_message));
            free(command);
            return NULL;
        }
    } else 
    {
        FILE *dest = fopen(full_path_pc, "wb");
        if (!dest) 
        {
            printf("DEBUG: Unable to open destination file '%s'. Unlocking mutex...\n", full_path_pc);
            fclose(source);
            pthread_mutex_unlock(&mutlock); 
            const char *error_message = "ERROR: Unable to open destination file.\n";
            SSL_write(ssl, error_message, strlen(error_message));
            free(command);
            return NULL;
        }

        
        char buffer[MAX_BUFFER];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), source)) > 0) {
            if (fwrite(buffer, 1, bytes_read, dest) != bytes_read) {
                printf("DEBUG: Error writing to destination file. Unlocking mutex...\n");
                fclose(source);
                fclose(dest);
                pthread_mutex_unlock(&mutlock); 
                const char *error_message = "ERROR: Write error to destination file.\n";
                SSL_write(ssl, error_message, strlen(error_message));
                free(command);
                return NULL;
            }
            fflush(dest);
        }
        fclose(dest);
    }

   
    fclose(source);

    printf("DEBUG: Unlocking mutex after successful file transfer...\n");
    pthread_mutex_unlock(&mutlock);

   
    const char *success_message = "File transfer successful.\n";
    SSL_write(ssl, success_message, strlen(success_message));

    printf("File %s sent to client.\n", filename);
    free(command);
    return NULL;
}


void *upload_file(void *args) 
{
    SSL *ssl = (SSL *)((void **)args)[0];
    char *command = (char *)((void **)args)[1];
    char filename[MAX_BUFFER];
    char path_server[MAX_BUFFER];
    char path_pc[MAX_BUFFER];

    if (!is_logged_in(ssl)) {
        const char *error_message = "ERROR: You are not logged in! Please login first.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        return NULL;
    }

    printf("DEBUG: Full command received: '%s'\n", command);
    int parsed = sscanf(command, "upload:%20s path_server:%100s path_pc:%100s", filename, path_server, path_pc);
    printf("DEBUG: sscanf parsed: %d\n", parsed);
    printf("DEBUG: Parsed values - filename: '%s', path_server: '%s', path_pc: '%s'\n", 
           filename, path_server, path_pc);

    if (parsed != 3) {
        const char *error_message = "ERROR: Invalid upload command format.\n Use: upload:filename path_server:path_server_allowed path_pc:your_path_pc\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        return NULL;
    }

    printf("DEBUG: Checking allowed path from server...\n");
    if (strcmp(path_server, allowed_path) != 0) {
        const char *error_message = "ERROR: Invalid server path! Only /home/nzapo/MySSH/Files is allowed.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        return NULL;
    }

    printf("Processing upload request for file: %s\n", filename);

    char full_path_pc[MAX_BUFFER];
    snprintf(full_path_pc, sizeof(full_path_pc), "%s/%s", path_pc, filename);


    if (access(full_path_pc, F_OK) == -1) {
        const char *error_message = "ERROR: File does not exist on your PC.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        return NULL;
    }


    char full_path_server[MAX_BUFFER];
    snprintf(full_path_server, sizeof(full_path_server), "%s/%s", path_server, filename);

    FILE *source = fopen(full_path_pc, "rb");
    if (!source) {
        const char *error_message = "ERROR: Unable to open source file.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        return NULL;
    }


    pthread_mutex_lock(&mutlock);


    FILE *dest = fopen(full_path_server, "wb");
    if (!dest) {
        pthread_mutex_unlock(&mutlock);
        const char *error_message = "ERROR: Unable to open destination file on server.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        fclose(source);
        free(command);
        return NULL;
    }

    char buffer[MAX_BUFFER];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), source)) > 0) {
        if (fwrite(buffer, 1, bytes_read, dest) != bytes_read) {
            pthread_mutex_unlock(&mutlock);
            const char *error_message = "ERROR: Write error to destination file.\n";
            SSL_write(ssl, error_message, strlen(error_message));
            fclose(source);
            fclose(dest);
            free(command);
            return NULL;
        }
        fflush(dest);
    }

   
    fclose(source);
    fclose(dest);

    printf("DEBUG: Unlocking mutex after successful file transfer...\n");
    pthread_mutex_unlock(&mutlock);

  
    const char *success_message = "File transfer successful.\n";
    SSL_write(ssl, success_message, strlen(success_message));

    printf("File %s uploaded to server.\n", filename);
    free(command);
    return NULL;
}

// ---Users can't access any path , just this path /home/nzapo/MySSH/Files
int validate_path(const char *path) 
{
    return strncmp(path, allowed_path, strlen(allowed_path)) == 0;
}


void remove_quotes(char *str) 
{
    int i, j = 0;
    for (i = 0; str[i] != '\0'; i++) 
    {
        if (str[i] != '\'' && str[i] != '"') 
        {
            str[j++] = str[i];
        }
    }
    str[j] = '\0';
}


int is_logged_in(SSL *ssl) 
{
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].ssl == ssl && users[i].auth == 1) 
        {
            return 1;
        }
    }

    return 0;
}

//-------hashing passwords with SHA-256-------------
char *hash_password(const char *password) 
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);
    char *output_hash = malloc((SHA256_DIGEST_LENGTH * 2) + 1);
    if (!output_hash) 
    {
        perror("Eroare la alocarea memoriei");
        return NULL;
    }
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) 
    {
        sprintf(output_hash + (i * 2), "%02x", hash[i]);
    }
    output_hash[SHA256_DIGEST_LENGTH * 2] = '\0';

    return output_hash;
}

//LOGIN---------------------------------------------
void *login_user(void *args) {
    SSL *ssl = (SSL *)((void **)args)[0];
    char *command = (char *)((void **)args)[1];
    char result[MAX_BUFFER] = {0};

    char username[50], password[70];
    char domain_suffix[6];
    
    printf("DEBUG: Full command received: '%s'\n", command);
    
    int parsed = sscanf(command, "login:%49[^@]@%5s password:%69s", 
                         username, domain_suffix, password);

    printf("DEBUG: sscanf parsed: %d\n", parsed);
    printf("DEBUG: Parsed values - username: '%s', domain_suffix: '%s', password: '%s'\n", 
            username, domain_suffix, password);
    
    if (parsed != 3) {
        const char *error_message = "ERROR: Invalid login command format. Use: login:username@MySSH password:password\n";
        SSL_write(ssl, error_message, strlen(error_message));
        return NULL;
    }
    
    printf("DEBUG: Checking domain...\n");
    if (strcmp(domain_suffix, "MySSH") != 0) 
    {
        const char *error_message = "ERROR: Invalid domain suffix\n";
        SSL_write(ssl, error_message, strlen(error_message));
        return NULL;
    }

    printf("DEBUG: Hashing password...\n");
    char *received_password_hash = hash_password(password);
    if (!received_password_hash) {
        const char *error_message = "ERROR: Failed to hash password\n";
        SSL_write(ssl, error_message, strlen(error_message));
        return NULL;
    }
    
    int user_found = 0;

    pthread_mutex_lock(&mutlock);

    if (is_logged_in(ssl)) 
        {
            const char *error_message = "ERROR: You are  logged in another account!.\n";
            SSL_write(ssl, error_message, strlen(error_message));
            free(command);
            pthread_mutex_unlock(&mutlock); 
            return NULL;
        }
    for (int i = 0; i < MAX_USERS; i++) 
    {
        if (users[i].username[0] != '\0' && users[i].password[0] != '\0') {
            printf("DEBUG: Checking user: %s with stored password: %s\n", users[i].username, users[i].password);
            if (strcmp(users[i].username, username) == 0 && strcmp(users[i].password, received_password_hash) == 0) {
                const char *success_message = "Login successful!\n";
                SSL_write(ssl, success_message, strlen(success_message));

                printf("DEBUG: User authenticated, updating user status...\n");
                
                users[i].auth = 1;
                users[i].ssl = ssl;
                user_found = 1;
                update_user_status(users[i].username, 1);
                break;
            }
        }
    }

    
    pthread_mutex_unlock(&mutlock);
   
    if (!user_found) {
        const char *error_message = "ERROR: Login failed, invalid username or password\n";
        SSL_write(ssl, error_message, strlen(error_message));
    }

    free(received_password_hash);
    return NULL;
}
//REGISTER------------------------------------------------------

void *register_user(void *args) 
{
    SSL *ssl = (SSL *)((void **)args)[0];
    char *command = (char *)((void **)args)[1];

    char username[50], password[70];
    char domain_suffix[6];

    int parsed = sscanf(command, "register:%49[^@]@%5s password:%69s", 
                         username, domain_suffix, password);

    if (parsed != 3) 
    {
        const char *error_message = "ERROR: Invalid register command format. Use: register:username@MySSH password:password\n";
        SSL_write(ssl, error_message, strlen(error_message));
        return NULL;
    }

   
    pthread_mutex_lock(&mutlock);

   
    for (int i = 0; i < MAX_USERS; i++) 
    {
        if (strcmp(users[i].username, username) == 0) 
        {
            const char *error_message = "ERROR: Username already exists\n";
            SSL_write(ssl, error_message, strlen(error_message));
            pthread_mutex_unlock(&mutlock);  
            return NULL;
        }
    }

    
    for (int i = 0; i < MAX_USERS; i++) 
    {
        if (users[i].username[0] == '\0') 
        {
            strncpy(users[i].username, username, sizeof(users[i].username) - 1);
            char *hashed_password = hash_password(password); 
            if (!hashed_password) 
            {
                const char *error_message = "ERROR: Failed to hash password\n";
                SSL_write(ssl, error_message, strlen(error_message));
                pthread_mutex_unlock(&mutlock);  
                return NULL;
            }
            strncpy(users[i].password, hashed_password, sizeof(users[i].password) - 1);
            users[i].auth = 0;
            users[i].ssl = NULL;
            free(hashed_password);

            const char *success_message = "Registration successful! You can now login.\n";
            SSL_write(ssl, success_message, strlen(success_message));
            save_users_to_file();
            pthread_mutex_unlock(&mutlock);  
            return NULL;
        }
    }

    const char *error_message = "ERROR: User limit reached. Cannot register more users.\n";
    SSL_write(ssl, error_message, strlen(error_message));

    pthread_mutex_unlock(&mutlock);  
    return NULL;
}

//LOGOUT------------------------------------------------------------------------------

void *logout_user(void *args) 
{
    SSL *ssl = (SSL *)((void **)args)[0];
    char *command = (char *)((void **)args)[1];
    char result[MAX_BUFFER] = {0};

    char username[50], password[70];
    char domain_suffix[6];
    
    printf("DEBUG: Full command received: '%s'\n", command);
    
    int parsed = sscanf(command, "logout:%49[^@]@%5s password:%69s", 
                         username, domain_suffix, password);

    printf("DEBUG: sscanf parsed: %d\n", parsed);
    printf("DEBUG: Parsed values - username: '%s', domain_suffix: '%s', password: '%s'\n", 
            username, domain_suffix, password);
    
    if (parsed != 3) {
        const char *error_message = "ERROR: Invalid logout command format. Use: logout:username@MySSH password:password\n";
        SSL_write(ssl, error_message, strlen(error_message));
        return NULL;
    }
    
    printf("DEBUG: Checking domain...\n");
    if (strcmp(domain_suffix, "MySSH") != 0) {
        const char *error_message = "ERROR: Invalid domain suffix\n";
        SSL_write(ssl, error_message, strlen(error_message));
        return NULL;
    }

    printf("DEBUG: Hashing password...\n");
    char *received_password_hash = hash_password(password);
    if (!received_password_hash) {
        const char *error_message = "ERROR: Failed to hash password\n";
        SSL_write(ssl, error_message, strlen(error_message));
        return NULL;
    }

    int user_found = 0;


    pthread_mutex_lock(&mutlock);
     if (!is_logged_in(ssl)) 
    {
        const char *error_message = "ERROR: You are not logged in! Please login first so you can logout:)).\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        pthread_mutex_unlock(&mutlock); 
        return NULL;
    }

    for (int i = 0; i < MAX_USERS; i++) 
    {
        if (users[i].username[0] != '\0' && users[i].password[0] != '\0') 
        {
            printf("DEBUG: Checking user: %s with stored password: %s\n", users[i].username, users[i].password);
            if (strcmp(users[i].username, username) == 0 && strcmp(users[i].password, received_password_hash) == 0) {
                const char *success_message = "Logout successful!\n";
                SSL_write(ssl, success_message, strlen(success_message));

                printf("DEBUG: User authenticated, logging out...\n");

                
                users[i].auth = 0;
                users[i].ssl = NULL;

                user_found = 1;

                update_user_status(users[i].username, 0);
                break;
            }
        }
    }

    
    pthread_mutex_unlock(&mutlock);

    if (!user_found) {
        const char *error_message = "ERROR: Logout failed, invalid username or password\n";
        SSL_write(ssl, error_message, strlen(error_message));
    }

    free(received_password_hash);
    return NULL;
}
//EXECUTE_COMMAND - cd,pwd are normal but the others (every command) - i used popen-------------------

void *execute_command(void *arg) 
{
    SSL *ssl = (SSL *)((void **)arg)[0];
    char *command = (char *)((void **)arg)[1];
    char result[MAX_BUFFER] = {0};
    FILE *fp;

    
    pthread_mutex_lock(&mutlock);

    // verifying if user is logged in
    if (!is_logged_in(ssl)) 
    {
        const char *error_message = "ERROR: You are not logged in! Please login first.\n";
        SSL_write(ssl, error_message, strlen(error_message));
        free(command);
        pthread_mutex_unlock(&mutlock);  
        return NULL;
    }

    // cd command handling
    if (strncmp(command, "cd ", 3) == 0) 
    {
        char path[MAX_BUFFER];
        strncpy(path, command + 3, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
        remove_quotes(path);

        if (!validate_path(path)) 
        {
            const char *error_message = "ERROR: Path not allowed!\n";
            SSL_write(ssl, error_message, strlen(error_message));
        } 
        else if (chdir(path) != 0) 
        {
            snprintf(result, sizeof(result), "ERROR: Unable to change directory to %s\n", path);
            SSL_write(ssl, result, strlen(result));
        } 
        else 
        {
            snprintf(result, sizeof(result), "Directory changed to %s\n", path);
            SSL_write(ssl, result, strlen(result));
        }
    } 
    // pwd command handling
    else if (strcmp(command, "pwd") == 0) 
    {
        if (getcwd(result, sizeof(result)) == NULL) 
        {
            const char *error_message = "ERROR: Unable to get current directory\n";
            SSL_write(ssl, error_message, strlen(error_message));
        } 
        else 
        {
            strncat(result, "\n", sizeof(result) - strlen(result) - 1);
            SSL_write(ssl, result, strlen(result));
        }
    }
    // Handling other commands
    else 
    {    
        // Get current directory
        char current_directory[MAX_BUFFER];
        if (getcwd(current_directory, sizeof(current_directory)) == NULL) 
        {
            const char *error_message = "ERROR: Unable to get current directory\n";
            SSL_write(ssl, error_message, strlen(error_message));
            pthread_mutex_unlock(&mutlock);
            return NULL;
        }

        // Verifying if user is in the allowed directory
        if (strcmp(current_directory, allowed_path) != 0) 
        {
            const char *error_message = "ERROR: Command execution is not allowed in the restricted directory.\n Please use the 'cd' command to change the directory.\n /home/nzapo/MySSH/Files\n";
            SSL_write(ssl, error_message, strlen(error_message));
            pthread_mutex_unlock(&mutlock);
            return NULL;
        }

        // Executing the command
        fp = popen(command, "r");
        if (!fp) 
        {
            const char *error_message = "ERROR: Command execution failed\n";
            SSL_write(ssl, error_message, strlen(error_message));
        } 
        else 
        {
            //all the command output will be stored in full_output buffer
            char full_output[MAX_BUFFER * 20] = {0}; 
            size_t total_length = 0;

            while (fgets(result, sizeof(result), fp) != NULL) 
            {
                size_t len = strlen(result);
                if (total_length + len < sizeof(full_output)) 
                {
                    memcpy(full_output + total_length, result, len);
                    total_length += len;
                }
                memset(result, 0, sizeof(result)); //
            }

            
            if (total_length > 0)
            {
                SSL_write(ssl, full_output, total_length);
            }

            int status = pclose(fp);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) 
            {
                
                if (total_length == 0) 
                {
                    const char *success_message = "Command successfully executed.\n";
                    SSL_write(ssl, success_message, strlen(success_message));
                } 
            } 
            else 
            {
              
                const char *error_message = "ERROR: Command failed with non-zero status\n";
                SSL_write(ssl, error_message, strlen(error_message));
            }
        }
    }

    free(command);

    
    pthread_mutex_unlock(&mutlock); 

    return NULL;
}
//------------------handling clients connections in separate
// threads for login,logout,execute_command and register
void *handle_client_thread(void *args) 
{
    ThreadArgs *thread_args = (ThreadArgs *)args;
    SSL *ssl = thread_args->ssl;

    char buffer[MAX_BUFFER] = {0};
    int bytes;
   
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) 
    {
        buffer[bytes] = '\0';
        char *command = strdup(buffer);
        if (!command) 
        {
            perror("ERROR: Memory allocation failed");
            SSL_write(ssl, "ERROR: Memory allocation failed\n", 31);
            continue;
        }

        pthread_t command_thread;

       
        if (strncmp(command, "login:", 6) == 0) 
        {
            void *args[] = {ssl, command};
            pthread_create(&command_thread, NULL, login_user, args);
        } 
        else if (strncmp(command, "register:", 9) == 0) 
        {
            void *args[] = {ssl, command};
            pthread_create(&command_thread, NULL, register_user, args);
        } 
        else if (strncmp(command, "logout:", 7) == 0)
        {
            void *args[] = {ssl, command};
            pthread_create(&command_thread, NULL, logout_user, args);
        }
        else if(strncmp(command,"download:",9)==0)
        {
          void *args[] = {ssl,command};
          pthread_create(&command_thread, NULL, handle_file_download, args);
        }
        else if (strncmp(command, "upload:", 7) == 0) 
        {
            void *args[] = {ssl, command};
            pthread_create(&command_thread, NULL, upload_file, args);
        }
        else if (strncmp(command, "quit", 4) == 0) 
        
           {printf("DEBUG: Full command received: '%s'\n", command);
            if (is_logged_in(ssl)) 
            {
                const char *error_message = "ERROR: You must logout before quitting.\n";
                SSL_write(ssl, error_message, strlen(error_message));

            } 
            else 
            {printf("shutdown\n");
            SSL_write(ssl, "quit", 4);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(thread_args->client_socket);
            free(thread_args);
            exit(0);
            return NULL;
            }
        }
        else 
        {
            void *args[] = {ssl, command};
            pthread_create(&command_thread, NULL, execute_command, args);
        }

        pthread_detach(command_thread); 
    }
   
    close(thread_args->client_socket);
    SSL_free(ssl);
    free(thread_args);

    return NULL;
}
//----------------------main------------------------------
int main() 
{   printf("DEBUG: ---------------------Starting server----------------------------\n");
    initialize_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);
    initialize_users();
    load_users_from_file();

for (int i = 0; i < MAX_USERS; i++) {
    if (users[i].username[0] != '\0') {
        printf("User  %d:\n", i);
        printf("Username: %s\n", users[i].username);
        printf("Password: %s\n", users[i].password);
        printf("Auth: %d\n", users[i].auth);
        printf("SSL: %p\n", users[i].ssl);
        printf("\n");
    }
}

// Creating server socket
int server_socket = socket(AF_INET, SOCK_STREAM, 0);
if (server_socket < 0)
{
    perror("ERROR: Cannot create server socket");
    exit(EXIT_FAILURE);
}


struct sockaddr_in server_addr;
memset(&server_addr, 0, sizeof(server_addr));
server_addr.sin_family = AF_INET;
server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Accepts connections from any IP address
server_addr.sin_port = htons(PORT);

if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
{
    perror("ERROR: Cannot bind server socket");
    close(server_socket);
    exit(EXIT_FAILURE);
}

if (listen(server_socket, 10) < 0) 
{
    perror("ERROR: Cannot listen on server socket");
    close(server_socket);
    exit(EXIT_FAILURE);
}

printf("Server started and listening on port %d\n", PORT);

while (1) 
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) 
    {
        perror("ERROR: Cannot accept connection");
        continue;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    if (SSL_accept(ssl) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        close(client_socket);
        SSL_free(ssl);
        continue;
    }

    ThreadArgs *thread_args = malloc(sizeof(ThreadArgs));
    thread_args->client_socket = client_socket;
    thread_args->ssl = ssl;

    pthread_t client_thread;
    pthread_create(&client_thread, NULL, handle_client_thread, thread_args);
    pthread_detach(client_thread);
}


close(server_socket);
SSL_CTX_free(ctx);
return 0;

}