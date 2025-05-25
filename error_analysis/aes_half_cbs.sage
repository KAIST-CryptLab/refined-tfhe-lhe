load("var.sage")
load("param.sage")

q = 2^64
n = 768

N_common = 256

Var_GLWE = stddev_2048^2
Var_LWE = stddev_768^2

B_ds = 2^4
l_ds = 3

amp_by_int_msg = 5

param1 = (
    "AES_HALF_CBS",
    # HalfCBS
    (3, 1024, stddev_4096^2), # (k_hc, N_hc, Var_hc_GLWE)
    (2^15, 3, 2^42), # (B_hc_tr, l_hc_tr, b_hc_tr)
    (2^13, 3), # (B_hc_ss, l_hc_ss)
    (2^7, 3), # (B_hc_ggsw, l_hc_ggsw)
    # CBS
    (2, 1024, stddev_2048^2), # (k, N, Var_GLWE)
    (2^23, 1), # (B_pbs, l_pbs)
    (2^12, 3, 2^64), # (B_tr, l_tr, b_tr)
    (2^17, 2), # (B_ss, l_ss)
    (2^2, 6), # (B_ggsw, l_ggsw)
    3, # theta
)

param2 = (
    "AES_HALF_CBS (high prec)",
    # HalfCBS
    (3, 1024, stddev_4096^2), # (k_hc, N_hc, Var_hc_GLWE)
    (2^15, 3, 2^42), # (B_hc_tr, l_hc_tr, b_hc_tr)
    (2^13, 3), # (B_hc_ss, l_hc_ss)
    (2^7, 3), # (B_hc_ggsw, l_hc_ggsw)
    # CBS
    (2, 1024, stddev_2048^2), # (k, N, Var_GLWE)
    (2^15, 2), # (B_pbs, l_pbs)
    (2^7, 6, 2^34), # (B_tr, l_tr, b_tr)
    (2^17, 2), # (B_ss, l_ss)
    (2^4, 4), # (B_ggsw, l_ggsw)
    2, # theta
)

param_list = [
    param1,
    param2,
]

for param in param_list:
    name = param[0]
    (k_hc, N_hc, Var_hc_GLWE) = param[1]
    (B_hc_tr, l_hc_tr, b_hc_tr) = param[2]
    (B_hc_ss, l_hc_ss) = param[3]
    (B_hc_ggsw, l_hc_ggsw) = param[4]
    (k, N, Var_GLWE) = param[5]
    (B_pbs, l_pbs) = param[6]
    (B_tr, l_tr, b_tr) = param[7]
    (B_ss, l_ss) = param[8]
    (B_ggsw, l_ggsw) = param[9]
    theta = param[10]

    print(f"======== {name} ========")
    print(f"n: {n}, Var_LWE: 2^{log(Var_LWE, 2).n():.4f}, B_ds: 2^{log(B_ds, 2).n()}, l_ds: {l_ds}")
    print(f"(HalfCBS Parameters)")
    print(f"  k: {k_hc}, N: {N_hc}, Var_GLWE: 2^{log(Var_hc_GLWE, 2).n():.4f}, B_tr: 2^{log(B_hc_tr, 2)}, l_tr: {l_hc_tr}, b_tr: 2^{log(b_hc_tr, 2)}, B_ss: 2^{log(B_hc_ss, 2)}, l_ss: {l_hc_ss}, B_ggsw: 2^{log(B_hc_ggsw, 2)}, l_ggsw: {l_hc_ggsw}")

    print(f"(CBS Parameters)")
    print(f"  k: {k}, N: {N}, Var_GLWE: 2^{log(Var_GLWE, 2).n():.4f}, B_tr: 2^{log(B_tr, 2)}, l_tr: {l_tr}, b_tr: 2^{log(b_tr, 2)}, B_ss: 2^{log(B_ss, 2)}, l_ss: {l_ss}, B_ggsw: 2^{log(B_ggsw, 2)}, l_ggsw: {l_ggsw}")
    print()

    print("==== 1st Round ====")
    Var_keyed_lut = q^2 * Var_hc_GLWE
    Var_linear = 4 * Var_keyed_lut
    print(f"Var_keyed_lut: 2^{log(Var_keyed_lut, 2).n():.4f}")
    print(f"Var_linear: 2^{log(Var_linear, 2).n():.4f}")

    print(f"\n==== 2nd Round (HalfCBS) ====")
    Var_tr = get_var_tr(N_hc, k_hc, q, Var_hc_GLWE, B_hc_tr, l_hc_tr)
    Var_auto_gadget = get_var_glwe_ks_gadget(N_hc, k_hc, q, B_hc_tr, l_hc_tr)
    Var_auto_key = get_var_glwe_ks_key(N_hc, k_hc, q, Var_GLWE, B_hc_tr, l_hc_tr)
    Var_fft_tr = get_var_fft_tr(N_hc, k_hc, B_hc_tr, l_hc_tr, b_hc_tr)
    Var_tr_tot = Var_tr + Var_fft_tr

    Var_split_fft_tr_upper = get_var_fft_glwe_ks(N_hc, k_hc, B_hc_tr, l_hc_tr, q / b_hc_tr)
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N_hc, k_hc, q, B_hc_tr, l_hc_tr, b_hc_tr)
    log_fp_split_fft = log(fp_split_fft, 2).n(10000)

    print(f"Var_tr_tot: 2^{log(Var_tr_tot, 2).n():.4f}")
    print(f"  - Var_tr:     2^{log(Var_tr, 2).n():.4f}")
    print(f"    - Var_auto_gadget: 2^{log(Var_auto_gadget, 2).n():.4f}")
    print(f"    - Var_auto_key   : 2^{log(Var_auto_key, 2).n():.4f}")
    print(f"  - Var_fft_tr: 2^{log(Var_fft_tr, 2).n():.4f}")
    print(f"  - F.P. of split fft: 2^{log_fp_split_fft:.4f} (stddev_upper: 2^{log(Var_split_fft_tr_upper, 2).n() / 2:.4f})")

    Var_ss_gadget = get_var_ss_gadget(N_hc, k_hc, q, B_hc_ss, l_hc_ss)
    Var_ss_key = get_var_ss_inc(N_hc, k_hc, q^2 * Var_hc_GLWE, B_hc_ss, l_hc_ss)
    Var_ss = get_var_ss(N_hc, k_hc, q, q^2 * Var_hc_GLWE, B_hc_ss, l_hc_ss)
    Var_fft_ss = get_var_fft_ext_prod(N_hc, k_hc, q, B_hc_ss, l_hc_ss)
    Var_ss_tot = Var_ss + Var_fft_ss

    print(f"Var_ss_tot: 2^{log(Var_ss_tot, 2).n():.4f}")
    print(f"  - Var_ss    : 2^{log(Var_ss, 2).n():.4f}")
    print(f"    - Var_ss_gadget: 2^{log(Var_ss_gadget, 2).n():.4f}")
    print(f"    - Var_ss_key   : 2^{log(Var_ss_key, 2).n():.4f}")
    print(f"  - Var_fft_ss: 2^{log(Var_fft_ss, 2).n():.4f}")

    Var_cbs = Var_linear + (N_hc/2) * Var_tr_tot + Var_ss_tot
    Var_cbs_amp = (N_hc/2) * Var_tr_tot

    print(f"Var_cbs: 2^{log(Var_cbs, 2).n():.4f}")
    print(f"  - (N/2) * Var_tr: 2^{log(Var_cbs_amp, 2).n():.4f}")
    print(f"  -         Var_ss: 2^{log(Var_ss_tot, 2).n():.4f}")

    Var_lut_ep_gadget = amp_by_int_msg * get_var_ext_prod_gadget(N_hc, k_hc, q, B_hc_ggsw, l_hc_ggsw)
    Var_lut_ep_inc = get_var_ext_prod_inc(N_hc, k_hc, Var_cbs, B_hc_ggsw, l_hc_ggsw)
    Var_fft_ep = get_var_fft_ext_prod(N_hc, k_hc, q, B_ggsw, l_ggsw)
    Var_lut_ep_tot = Var_lut_ep_gadget + Var_lut_ep_inc + Var_fft_ep

    print("8-bit keyed-LUT")
    print(f"  - Integer amplification in average: {amp_by_int_msg:.1f}")
    print(F"  - Var_lut_ep_tot: 2^{log(Var_lut_ep_tot, 2).n():.4f}")
    print(f"    - Var_lut_ep_gadget: 2^{log(Var_lut_ep_gadget, 2).n():.4f} (integer message)")
    print(f"    - Var_lut_ep_inc   : 2^{log(Var_lut_ep_inc, 2).n():.4f}")
    print(f"    - Var_fft_ep       : 2^{log(Var_fft_ep, 2).n():.4f}")

    Var_lut_out = 0
    for i in range(8):
        Var_lut_out *= amp_by_int_msg
        print(f"  [{i+1}] Amp: 2^{log(Var_lut_out, 2).n():.4f}")
        Var_lut_out += Var_lut_ep_tot
        print(f"      Inc: 2^{log(Var_lut_out, 2).n():.4f}")

    Var_linear = 4 * Var_lut_out + q^2 * Var_hc_GLWE
    print(f"Var_linear: 2^{log(Var_linear, 2).n():.4f}")

    k_src = (k_hc * N_hc) // N_common
    Var_lwe_ks = get_var_glwe_ks(N_common, k_src, q, Var_LWE, B_ds, l_ds)
    Var_lwe_ks_gadget = get_var_glwe_ks_gadget(N_common, k_src, q, B_ds, l_ds)
    Var_lwe_ks_key = get_var_glwe_ks_key(N_common, k_src, q, Var_LWE, B_ds, l_ds)
    Var_lwe_ks_fft = get_var_fft_glwe_ks(N_common, k_src, B_ds, l_ds, q)
    Var_lwe_ks_tot = Var_lwe_ks + Var_lwe_ks_fft
    print(f"Var_lwe_ks_tot: 2^{log(Var_lwe_ks_tot, 2).n():.4f}")
    print(f"  - Var_lwe_ks    : 2^{log(Var_lwe_ks, 2).n():.4f}")
    print(f"    - Var_lwe_ks_gadget: 2^{log(Var_lwe_ks_gadget, 2).n():.4f}")
    print(f"    - Var_lwe_ks_key   : 2^{log(Var_lwe_ks_key, 2).n():.4f}")
    print(f"  - Var_lwe_ks_fft: 2^{log(Var_lwe_ks_fft).n():.4f}")


    Var_pbs_in = Var_linear + Var_lwe_ks_tot
    print()
    print(f"Var_pbs_in: 2^{log(Var_pbs_in, 2).n():.4f}")

    w = 2*N_hc/(2^theta)
    q_prime = q
    delta_in = 2^63

    Gamma, fp = get_fp_pbs(n, q_prime, N_hc, theta, delta_in, Var_linear)
    log_fp = log(fp, 2).n(1000)
    print(f"F.P. of next PBS with theta = {theta}: Gamma = {Gamma}, f.p. = 2^{log_fp:.4f}")


    print(f"\n==== 3rd Round (CBS) ====")
    Var_pbs = get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
    Var_pbs_fft = get_var_fft_pbs(N, k, n, B_pbs, l_pbs)
    Var_pbs_tot = Var_pbs + Var_pbs_fft
    print(f"Var_pbs_tot: 2^{log(Var_pbs_tot, 2).n():.4f}")
    print(f"  - Var_pbs    : 2^{log(Var_pbs, 2).n():.4f}")
    print(f"  - Var_pbs_fft: 2^{log(Var_pbs_fft, 2).n():.4f}")

    Var_tr = get_var_tr(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_auto_gadget = get_var_glwe_ks_gadget(N, k, q, B_tr, l_tr)
    Var_auto_key = get_var_glwe_ks_key(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_fft_tr = get_var_fft_tr(N, k, B_tr, l_tr, q)
    Var_tr_tot = Var_tr + Var_fft_tr

    Var_split_fft_tr_upper = get_var_fft_glwe_ks(N, k, B_tr, l_tr, q / b_tr)
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_tr, l_tr, b_tr)
    log_fp_split_fft = log(fp_split_fft, 2).n(10000)

    print(f"Var_tr_tot: 2^{log(Var_tr_tot, 2).n():.4f}")
    print(f"  - Var_tr:     2^{log(Var_tr, 2).n():.4f}")
    print(f"    - Var_auto_gadget: 2^{log(Var_auto_gadget, 2).n():.4f}")
    print(f"    - Var_auto_key   : 2^{log(Var_auto_key, 2).n():.4f}")
    print(f"  - Var_fft_tr: 2^{log(Var_fft_tr, 2).n():.4f}")
    print(f"  - F.P. of split fft: 2^{log_fp_split_fft:.4f} (stddev_upper: 2^{log(Var_split_fft_tr_upper, 2).n() / 2:.4f})")

    Var_ss_gadget = get_var_ss_gadget(N, k, q, B_ss, l_ss)
    Var_ss_key = get_var_ss_inc(N, k, q^2 * Var_GLWE, B_ss, l_ss)
    Var_ss = get_var_ss(N, k, q, q^2 * Var_GLWE, B_ss, l_ss)
    Var_fft_ss = get_var_fft_ext_prod(N, k, q, B_ss, l_ss)
    Var_ss_tot = Var_ss + Var_fft_ss

    print(f"Var_ss_tot: 2^{log(Var_ss_tot, 2).n():.4f}")
    print(f"  - Var_ss    : 2^{log(Var_ss, 2).n():.4f}")
    print(f"    - Var_ss_gadget: 2^{log(Var_ss_gadget, 2).n():.4f}")
    print(f"    - Var_ss_key   : 2^{log(Var_ss_key, 2).n():.4f}")
    print(f"  - Var_fft_ss: 2^{log(Var_fft_ss, 2).n():.4f}")

    Var_cbs = Var_pbs_tot + (N/2) * Var_tr_tot + Var_ss_tot
    Var_cbs_amp = (N/2) * Var_tr_tot

    print(f"Var_cbs: 2^{log(Var_cbs, 2).n():.4f}")
    print(f"  - Var_pbs_tot        : 2^{log(Var_pbs_tot, 2).n():.4f}")
    print(f"  -  (N/2) * Var_tr_tot: 2^{log(Var_cbs_amp, 2).n():.4f}")
    print(f"  -          Var_ss_tot: 2^{log(Var_ss_tot, 2).n():.4f}")

    Var_lut_ep = get_var_ext_prod(N, k, q, Var_cbs, B_ggsw, l_ggsw)
    Var_lut_ep_gadget = get_var_ext_prod_gadget(N, k, q, B_ggsw, l_ggsw)
    Var_lut_ep_inc = get_var_ext_prod_inc(N, k, Var_cbs, B_ggsw, l_ggsw)
    Var_fft_ep = get_var_fft_ext_prod(N, k, q, B_ggsw, l_ggsw)
    Var_lut_ep_tot = Var_lut_ep + Var_fft_ep

    print(f"Var_ep_tot: 2^{log(Var_lut_ep_tot, 2).n():.4f}")
    print(f"  - Var_ep    : 2^{log(Var_lut_ep, 2).n():.4f}")
    print(f"    - Var_ep_gadget: 2^{log(Var_lut_ep_gadget, 2).n():.4f}")
    print(f"    - Var_ep_inc   : 2^{log(Var_lut_ep_inc, 2).n():.4f}")
    print(f"  - Var_fft_ep: 2^{log(Var_fft_ep, 2).n():.4f}")

    Var_8_lut = 8 * Var_lut_ep_tot
    Var_linear = 4 * Var_8_lut
    print(f"Var_8_lut : 2^{log(Var_8_lut, 2).n():.4f}")
    print(f"Var_linear: 2^{log(Var_linear, 2).n():.4f}")

    k_src = (k * N) // N_common
    Var_lwe_ks = get_var_glwe_ks(N_common, k_src, q, Var_LWE, B_ds, l_ds)
    Var_lwe_ks_gadget = get_var_glwe_ks_gadget(N_common, k_src, q, B_ds, l_ds)
    Var_lwe_ks_key = get_var_glwe_ks_key(N_common, k_src, q, Var_LWE, B_ds, l_ds)
    Var_lwe_ks_fft = get_var_fft_glwe_ks(N_common, k_src, B_ds, l_ds, q)
    Var_lwe_ks_tot = Var_lwe_ks + Var_lwe_ks_fft
    print(f"Var_lwe_ks_tot: 2^{log(Var_lwe_ks_tot, 2).n():.4f}")
    print(f"  - Var_lwe_ks    : 2^{log(Var_lwe_ks, 2).n():.4f}")
    print(f"    - Var_lwe_ks_gadget: 2^{log(Var_lwe_ks_gadget, 2).n():.4f}")
    print(f"    - Var_lwe_ks_key   : 2^{log(Var_lwe_ks_key, 2).n():.4f}")
    print(f"  - Var_lwe_ks_fft: 2^{log(Var_lwe_ks_fft).n():.4f}")

    Var_pbs_in = Var_linear + Var_lwe_ks_tot + q^2 * Var_GLWE
    print()
    print(f"Var_pbs_in: 2^{log(Var_pbs_in, 2).n():.4f}")

    Gamma, fp = get_fp_pbs(n, q_prime, N, theta, delta_in, Var_linear)
    log_fp = log(fp, 2).n(1000)
    print(f"F.P. of next PBS with theta = {theta}: Gamma = {Gamma}, f.p. = 2^{log_fp:.4f}")
    print()
    print()
