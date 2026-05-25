#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <systemd/sd-bus.h>

#include <pthread.h>
#include <unistd.h>
#include <termios.h>

#include <stdio.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
    pam_handle_t *pamh;
    const char *user;
    atomic_bool done;
    atomic_int result;
} auth_data;

int fprint_match(sd_bus_message *m, void *args, sd_bus_error *ret_error) {
    auth_data *data = (auth_data*)args;

    const char *result;
    int r = sd_bus_message_read(m, "sb", &result, NULL);
    if (r < 0) 
        return 0;
    
    atomic_store(&data->result, 1);
    atomic_store(&data->done, true);

    return 0;
}

void *check_fingerprint(void* ptr) {
    auth_data *data = (auth_data*)ptr;

retry:
    sd_bus *bus = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *msg = NULL;
    char *device_path = NULL;

    // Connect to sd-bus
    if (sd_bus_open_system(&bus) < 0) return NULL;

    // Get default fprintd device path
    int r = sd_bus_call_method(
        bus,
        "net.reactivated.Fprint",
        "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager",
        "GetDefaultDevice",
        &error,
        &msg,
        "");
    if (r < 0) goto cleanup;
    sd_bus_message_read(msg, "o", &device_path);

    // Claim device
    r = sd_bus_call_method(
        bus,
        "net.reactivated.Fprint",
        device_path,
        "net.reactivated.Fprint.Device",
        "Claim",
        &error,
        NULL,
        "s",
        data->user);
    if (r < 0) {
        if (sd_bus_error_has_name(&error, "net.reactivated.Fprint.Error.AlreadyInUse")) {
            usleep(1000000); // Wait 1s before retrying
            goto retry;
        }

        goto cleanup;
    }

    // Start verification
    r = sd_bus_call_method(
        bus,
        "net.reactivated.Fprint",
        device_path,
        "net.reactivated.Fprint.Device",
        "VerifyStart",
        &error,
        NULL,
        "s",
        "any");
    if (r < 0) goto cleanup;

    // Start listening for verification result
    sd_bus_slot *slot = NULL;
    sd_bus_add_match(
        bus,
        &slot,
        "type='signal',interface='net.reactivated.Fprint.Device',member='VerifyStatus'",
        fprint_match,
        data);

    // Event loop
    while (atomic_load(&data->done) == false) {
        r = sd_bus_process(bus, NULL);
        if (r <= 0) {
            r = sd_bus_wait(bus, 100000);
            if (r < 0) break;
        }
    }

    if (slot)
        sd_bus_slot_unref(slot);

cleanup:
    // Release and close
    if (device_path) {
        sd_bus_call_method(
            bus,
            "net.reactivated.Fprint",
            device_path, 
            "net.reactivated.Fprint.Device",
            "Release",
            &error,
            NULL,
            "");
    }
    sd_bus_error_free(&error);
    sd_bus_message_unref(msg);
    sd_bus_unref(bus);

    return NULL;
}

void* check_password(void* ptr) {
    auth_data *data = (auth_data*)ptr;

    // Password prompt
    const char *password;
    int rc = pam_get_authtok(data->pamh, PAM_AUTHTOK, &password, "Fingerprint or Password: ");
    if (rc == PAM_SUCCESS) {
        // Pass password to pam_unix.so
        pam_set_item(data->pamh, PAM_AUTHTOK, password);
        atomic_store(&data->result, 2);
    }

    // Finish execution
    atomic_store(&data->done, true);

    return NULL;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Check if terminal
    int term = isatty(0);

    // Get user
    const char *user;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS)
        return PAM_USER_UNKNOWN;

    // Create thread args
    auth_data *data = malloc(sizeof(auth_data));
    data->pamh = pamh;
    data->user = user;
    data->done = false;
    data->result = 0;

    // Create threads
    pthread_t pw_thread, fp_thread;
    pthread_create(&pw_thread, NULL, check_password, data);
    pthread_create(&fp_thread, NULL, check_fingerprint, data);

    // Wait for either thread to complete authentication
    while (!data->done)
        usleep(10000);

    // Stop all threads
    pthread_cancel(pw_thread);
    pthread_join(pw_thread, NULL);
    pthread_join(fp_thread, NULL);

    // Return PAM_SUCCESS to authenticate successfully (fingerprint match)
    if (atomic_load(&data->result) == 1) {
        if (term)
            printf("\n");
        free(data);
        return PAM_SUCCESS;
    }
    else if (atomic_load(&data->result) == 2) {
        free(data);
        return PAM_IGNORE;
    }

    // Fail safe
    free(data);
    return PAM_AUTH_ERR;
}

// Not needed
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
