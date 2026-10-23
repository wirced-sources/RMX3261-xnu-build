/* SPDX-License-Identifier: MIT
 * Explicit unsupported-service boundary, preserving the original HFS ENXIO
 * outcome when key_services()/its callback is absent. No outputs or key bytes
 * are synthesized, and the original content-protection checks remain active.
 */
int hfs_unwrap_key(rmx_hfs_key_cred_t access,const cp_wrapped_key_t input,cp_raw_key_t output)
{
    (void)access; (void)input; (void)output;
    return ENXIO;
}
int hfs_rewrap_key(rmx_hfs_key_cred_t access,cp_key_class_t klass,
                  const cp_wrapped_key_t input,cp_wrapped_key_t output)
{
    (void)access; (void)klass; (void)input; (void)output;
    return ENXIO;
}
int hfs_new_key(rmx_hfs_key_cred_t access,cp_key_class_t klass,
               cp_raw_key_t raw,cp_wrapped_key_t wrapped)
{
    (void)access; (void)klass; (void)raw; (void)wrapped;
    return ENXIO;
}
int hfs_backup_key(rmx_hfs_key_cred_t access,const cp_wrapped_key_t input,cp_wrapped_key_t output)
{
    (void)access; (void)input; (void)output;
    return ENXIO;
}
