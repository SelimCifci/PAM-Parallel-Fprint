// PAM related headers
#include <security/_pam_types.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

// Fprint related headers
#include <systemd/sd-bus.h>

// Misc headers
#include <termios.h>

// Structure to pass data to threads
typedef struct {
    pam_handle_t *pamh;
    const char *user;
    int result;
    int done;
} auth_data;

static int fprint_match(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
    auth_data *data = (auth_data*)userdata;
    const char *result;
    int boolean_done;

    if (sd_bus_message_is_signal(m, "net.reactivated.Fprint.Device", "VerifyStatus")) {
        int r = sd_bus_message_read(m, "sb", &result, &boolean_done);
        if (r >= 0 && strcmp(result, "verify-match") == 0) {
            data->result = 1; // Fingerprint matched
            data->done = 1;
        }
    }

    return 0;
}

void* check_fingerprint(void* ptr) {
    auth_data *data = (auth_data*)ptr;
retry:
    // SD-BUS setup
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    char *device_path = NULL;

    // Connect to the system bus
    if (sd_bus_open_system(&bus) < 0) return NULL;

    // Get default fprintd device path
    int r = sd_bus_call_method(bus,
                               "net.reactivated.Fprint",
                               "/net/reactivated/Fprint/Manager",
                               "net.reactivated.Fprint.Manager",
                               "GetDefaultDevice",
                               &error,
                               &m,
                               "");
    // Check for errors
    if (r < 0) goto cleanup;

    sd_bus_message_read(m, "o", &device_path);

    // Claim device
    r = sd_bus_call_method(bus,
                           "net.reactivated.Fprint",
                           device_path,
                           "net.reactivated.Fprint.Device",
                           "Claim",
                           &error,
                           NULL,
                           "s", data->user);
    if (r < 0) {
        if (sd_bus_error_has_name(&error, "net.reactivated.Fprint.Error.AlreadyInUse")) {
            usleep(1000000); // Wait 1s before retrying
            goto retry;
        }

        goto cleanup;
    }

    // Start verification
    r = sd_bus_call_method(bus,
                           "net.reactivated.Fprint",
                           device_path,
                           "net.reactivated.Fprint.Device",
                           "VerifyStart",
                           &error,
                           NULL,
                           "s", "any");
    if (r < 0) goto cleanup;

    // Listen for verification result
    sd_bus_slot *slot = NULL;
    sd_bus_add_match(bus,
                     &slot,
                     "type='signal',interface='net.reactivated.Fprint.Device',member='VerifyStatus'",
                     fprint_match,
                     data);

    // Event loop
    while (data->done == 0) {
        r = sd_bus_process(bus, NULL);
        if (r < 0) break; // Error
        if (r > 0) continue; // We processed something, check again immediately

        // Nothing to process, wait for the next event (max 1 second)
        r = sd_bus_wait(bus, 100000);
        if (r < 0) break;
    }

    if (slot) sd_bus_slot_unref(slot);

cleanup:
    // Release and Close
    if (device_path) {
        sd_bus_call_method(bus, "net.reactivated.Fprint", device_path, 
                           "net.reactivated.Fprint.Device", "Release", &error, NULL, "");
    }
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return NULL;
}

void* check_password(void* ptr) {
    auth_data *data = (auth_data*)ptr;

    // Password prompt
    const char *password;
    int rc = pam_get_authtok(data->pamh, PAM_AUTHTOK, &password, "Fingeprint or Password: ");

    // Set password for pam_unix.so
    if (rc == PAM_SUCCESS) {
        pam_set_item(data->pamh, PAM_AUTHTOK, password);
        data->result = 2;
    }
    data->done = 1;

    return NULL;
}

// Custom stuff
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // -----INITIALIZATION-----
    // Get user
    const char *user;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) return PAM_USER_UNKNOWN;

    // Create shared data structure for threads
    auth_data data = {pamh, user, 0, 0 };
    pthread_t fp_thread, pw_thread;
    
    // -----THREAD CREATION-----
    pthread_create(&fp_thread, NULL, check_fingerprint, &data);
    pthread_create(&pw_thread, NULL, check_password, &data);

    // Wait for either thread to complete authentication
    while (!data.done) {
        usleep(50000); // Sleep for 50ms
    }

    // -----Clean up-----
    pthread_cancel(pw_thread);
    pthread_join(fp_thread, NULL);
    pthread_join(pw_thread, NULL);
    tcflush(STDIN_FILENO, TCIFLUSH);

    // Return PAM_SUCCESS to authenticate successfully (fingeprint match)
    if (data.result == 1) {
        printf("\n");
        return PAM_SUCCESS;
    }
    // Return PAM_IGNORE so pam_unix.so can take over password authentication
    else if (data.result == 2) return PAM_IGNORE;

    // FAIL SAFE
    return PAM_AUTH_ERR;
}

// Expected PAM functions --NOT NEEDED--
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

