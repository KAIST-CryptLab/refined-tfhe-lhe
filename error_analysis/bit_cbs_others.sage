load('var.sage')
load('param.sage')

WOPBS_1_1 = (
    "WOPBS_1_1",
    (653, 0.00003604499526942373^2), # Level 0 (n, Var_LWE)
    (2048, 1, 0.00000000000000029403601535432533^2), # Level 1 (N, k, Var_GLWE)
    (2048, 1, 0.00000000000000029403601535432533^2), # Level 2 (N, k, Var_GLWE)
    (2^15, 2), # (B_pbs, l_pbs)
    (2^5, 2), # (B_ks, l_ks)
    (2^15, 2), # (B_pfks, l_pfks)
    (2^5, 3), # (B_cbs, l_cbs)
    False, # precopmute
)

WOPBS_1_0 = (
    "WOPBS_1_0",
    (498, 0.00044851669823869648209^2), # Level 0 (n, Var_LWE)
    (1024, 2, 0.00000000000000029403601535432533^2), # Level 1 (N, k, Var_GLWE)
    (1024, 2, 0.00000000000000029403601535432533^2), # Level 2 (N, k, Var_GLWE)
    (2^24, 1), # (B_pbs, l_pbs)
    (2^2, 4), # (B_ks, l_ks)
    (2^24, 1), # (B_pfks, l_pfks)
    (2^2, 5), # (B_cbs, l_cbs)
    False, # precopmute
)

TFHEPP = (
    "TFHEpp",
    (635, 2^-30), # Level 0 (n, Var_LWE)
    (1024, 1, 2^-50), # Level 1 (N, k, Var_GLWE)
    (2048, 1, 2^-88), # Level 2 (N, k, Var_GLWE)
    (2^9, 4), # (B_pbs, l_pbs)
    (2^2, 7), # (B_ks, l_ks)
    (2^3, 10), # (B_pfks, l_pfks)
    (2^6, 3), # (B_cbs, l_cbs)
    True, # precompute
)

MOSFHET_SET2 = (
    "MOSFHET SET2 (need to update RLWE KS)",
    (744, (7.747831515176779e-6)^2), # Level 0 (n, Var_LWE)
    (2048, 1, (2.2148688116005568e-16)^2), # Level 1 (N, k, Var_GLWE)
    (2048, 1, (2.2148688116005568e-16)^2), # Level 2 (N, k, Var_GLWE)
    (2^23, 1), # (B_pbs, l_pbs)
    (2^2, 7), # (B_ks, l_ks)
    (2^3, 5), # (B_pfks, l_pfks)
    (2^23, 1), # (B_cbs, l_cbs)
    True, # precompute
)

MOSFHET_SET3 = (
    "MOSFHET SET3 (need to update RLWE KS)",
    (807, (1.0562341599676662e-6)^2), # Level 0 (n, Var_LWE)
    (4096, 1, (2.168404344971009e-19)^2), # Level 1 (N, k, Var_GLWE)
    (4096, 1, (2.168404344971009e-19)^2), # Level 2 (N, k, Var_GLWE)
    (2^22, 1), # (B_pbs, l_pbs)
    (2^2, 7), # (B_ks, l_ks)
    (2^3, 5), # (B_pfks, l_pfks)
    (2^22, 1), # (B_cbs, l_cbs)
    True, # precompute
)

MOSFHET_SET4 = (
    "MOSFHET SET4 (need to update RLWE KS)",
    (635, 2^-30), # Level 0 (n, Var_LWE)
    (2048, 1, 2^-88), # Level 2 (N, k, Var_GLWE)
    (2048, 1, 2^-88), # Level 2 (N, k, Var_GLWE)
    (2^9, 4), # (B_pbs, l_pbs)
    (2^2, 7), # (B_ks, l_ks)
    (2^4, 8), # (B_pfks, l_pfks)
    (2^4, 8), # (B_cbs, l_cbs)
    True, # precompute
    (2^4, 10), # (B_ss, l_ss)
)

param_list = [
    # WOPBS_1_0,
    WOPBS_1_1,
    TFHEPP,
    # MOSFHET_SET2,
    # MOSFHET_SET3,
    MOSFHET_SET4,
]


q = 2^64
log_fp_thrs_list = [-32, -40]

for param in param_list:
    name = param[0]
    (n, Var_LWE) = param[1]
    (N1, k1, Var_level1) = param[2]
    (N2, k2, Var_level2) = param[3]
    (B_pbs, l_pbs) = param[4]
    (B_ks, l_ks) = param[5]
    (B_pfks, l_pfks) = param[6]
    (B_cbs, l_cbs) = param[7]
    is_pre = param[8]

    is_ss = len(param) == 10
    if is_ss:
        (B_ss, l_ss) = param[9]
    print(f"======== {name} ========")

    Var_lwe_ks = get_var_lwe_ks(N1, k1, q, Var_LWE, B_ks, l_ks)
    print(f"Var_lwe_ks: 2^{log(Var_lwe_ks, 2).n():.4f}")
    print()

    Var_pbs = get_var_pbs(N2, k2, n, q, Var_level2, B_pbs, l_pbs)
    Var_pbs_gadget = get_var_pbs_gadget(N2, k2, n, q, B_pbs, l_pbs)
    Var_pbs_key = get_var_pbs_key(N2, k2, n, q, Var_level2, B_pbs, l_pbs)
    Var_fft_pbs = get_var_fft_pbs(N2, k2, n, B_pbs, l_pbs)
    Var_pbs_tot = Var_pbs + Var_fft_pbs

    print(f"Var_pbs_tot: 2^{log(Var_pbs_tot, 2).n():.4f}")
    print(f"  - Var_pbs: 2^{log(Var_pbs, 2).n():.4f}")
    print(f"    - Var_pbs_gadget: 2^{log(Var_pbs_gadget, 2).n():.4f}")
    print(f"    - Var_pbs_key   : 2^{log(Var_pbs_key, 2).n():.4f}")
    print(f"  - Var_fft_pbs: 2^{log(Var_fft_pbs, 2).n():.4f}")
    print()

    Bp_2l_pfks = B_pfks^(2*l_ks)
    B2_12_pfks = B_pfks^2 / 12
    Var_pfks_gadget = (N1 * k1) * ((q^2 - Bp_2l_pfks) / (24*Bp_2l_pfks) + 1/16)
    Var_pfks_key = (N1 * k1) * l_pfks * (q^2 * Var_level1) * (B2_12_pfks + 1/6)
    Var_pfks_key_precomp = (N1 * k1) * l_pfks * (q^2 * Var_level1) / 4

    if is_pre:
        Var_pfks = Var_pfks_gadget + Var_pfks_key_precomp
        print(f"Var_pfks (precomp): 2^{log(Var_pfks, 2).n():.4f}")
    else:
        Var_pfks = Var_pfks_gadget + Var_pfks_key
        print(f"Var_pfks: 2^{log(Var_pfks, 2).n():.4f}")
    print()

    if is_ss:
        Var_ss_gadget = get_var_ss_gadget(N1, k1, q, B_ss, l_ss)
        Var_ss_inc = get_var_ss_inc(N1, k1, q^2 * Var_level1, B_ss, l_ss)
        Var_fft_ss = get_var_fft_ss(N1, k1, q, B_ss, l_ss)
        Var_ss_tot = Var_ss_gadget + Var_ss_inc + Var_fft_ss

        print(f"Var_ss_tot: 2^{log(Var_ss_tot, 2).n():.4f}")
        print(f"  - Var_ss_gadget: 2^{log(Var_ss_gadget, 2).n():.4f}")
        print(f"  - Var_ss_inc   : 2^{log(Var_ss_inc, 2).n():.4f}")
        print(f"  - Var_fft_ss   : 2^{log(Var_fft_ss, 2).n():.4f}")
        print()

        Var_cbs = Var_pbs_tot + Var_ss_tot + Var_pfks * (N1/2)
    else:
        Var_cbs = Var_pbs_tot + Var_pfks

    Var_add = get_var_ext_prod(N1, k1, q, Var_cbs, B_cbs, l_cbs)
    Var_fft_add = get_var_fft_ext_prod(N1, k1, q, B_cbs, l_cbs)
    Var_add_tot = Var_add + Var_fft_add

    print(f"Var_cbs    : 2^{log(Var_cbs, 2).n():.4f}")
    print(f"Var_add_tot: 2^{log(Var_add_tot, 2).n():.4f}")
    print(f"  - Var_add    : 2^{log(Var_add, 2).n():.4f}")
    print(f"  - Var_fft_add: 2^{log(Var_fft_add, 2).n():.4f}")
    print()

    print("max-depth for")
    for log_fp_thrs in log_fp_thrs_list:
        log_var_thrs = find_var_thrs(n, q, N2, 1, 2^63, log_fp_thrs)
        Var_thrs = 2^log_var_thrs
        max_depth = ((Var_thrs - Var_lwe_ks) / Var_add_tot).n()
        print(f"  - F.P. of 2^{log_fp_thrs}: {max_depth}")
    print()


