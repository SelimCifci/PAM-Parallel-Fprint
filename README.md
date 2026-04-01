# PAM-Parallel-Fprint
A Linux-PAM module that allows for fingerprint (fprintd) and password authorization in parallel
- Does and will not work with SDDM because of the way SDDM handles PAM authorization

# Installation
- Run the `ìnstall.sh` script
- Add the 2 lines in `add_to_pam` to your PAM files (located in `/etc/pam.d/`)
