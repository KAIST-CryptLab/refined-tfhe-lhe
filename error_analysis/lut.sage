load("var.sage")
load("param.sage")

q = 2^64
N = 2048
k = 1
Var_GLWE = stddev_2048^2


param_list = [
    improved_wopbs_2_2,
]

for param in param_list:
    name = param[0]
    (n, Var_LWE) = param[1]
    (B_pbs, l_pbs) = param[2]
    (B_tr, l_tr, b_tr) = param[3]
    (B_ss, l_ss) = param[4]
    (B_cbs, l_cbs) = param[5]
    (B_ksk, l_ksk) = param[6]
    theta = param[7]
    log_modulus = param[8]
    max_num_extract = param[9]

    print(f"========================= {name} =========================")
    print(f"n: {n}, N: {N}, k: {k}, B_pbs: 2^{log(B_pbs, 2)}, l_pbs: {l_pbs}\n")

    Var_pbs = get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
    Var_fft_pbs = get_var_fft_pbs(N, k, n, B_pbs, l_pbs)
    Var_pbs_tot = Var_pbs + Var_fft_pbs
    Var_ks = get_var_lwe_ks(N, k, q, Var_LWE, B_ksk, l_ksk)

    Var_tr = get_var_tr(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_auto_gadget = get_var_glwe_ks_gadget(N, k, q, B_tr, l_tr)
    Var_auto_key = get_var_glwe_ks_key(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_fft_tr = get_var_fft_tr(N, k, B_tr, l_tr, b_tr)
    Var_tr_tot = Var_tr + Var_fft_tr

    Var_ss = get_var_ss(N, k, q, q^2 * Var_GLWE, B_ss, l_ss)
    Var_fft_ss = get_var_fft_ext_prod(N, k, q, B_ss, l_ss)
    Var_ss_tot = Var_ss + Var_fft_ss

    Var_cbs = Var_pbs_tot + Var_ss_tot + (N/2) * Var_tr_tot
    Var_cbs_additive = Var_pbs_tot + Var_ss_tot
    Var_cbs_amp = (N/2) * Var_tr_tot

    Var_Add = get_var_ext_prod(N, k, q, Var_cbs, B_cbs, l_cbs) + get_var_fft_ext_prod(N, k, q, B_cbs, l_cbs)
    Var_add_gadget = get_var_ext_prod_gadget(N, k, q, B_cbs, l_cbs)
    Var_add_inc = get_var_ext_prod_inc(N, k, Var_cbs, B_cbs, l_cbs)
    Var_fft_add = get_var_fft_ext_prod(N, k, q, B_cbs, l_cbs)

    print(f"Var_ks: 2^{log(Var_ks, 2).n():.4f}")
    print(f"Var_pbs_tot: 2^{log(Var_pbs_tot, 2).n():.4f}")
    print(f"  - Var_pbs: 2^{log(Var_pbs, 2).n():.4f}")
    print(f"  - Var_fft_pbs: 2^{log(Var_fft_pbs, 2).n():.4f}")
    print(f"Var_tr_tot : 2^{log(Var_tr_tot, 2).n():.4f}")
    print(f"  - Var_tr: 2^{log(Var_tr, 2).n():.4f}")
    print(f"     - Var_auto_gadget: 2^{log(Var_auto_gadget, 2).n():.4f}")
    print(f"     - Var_auto_key: 2^{log(Var_auto_key, 2).n():.4f}")
    print(f"  - Var_fft_tr: 2^{log(Var_fft_tr, 2).n():.4f}")
    print(f"Var_ss_tot: 2^{log(Var_ss_tot, 2).n():.4f}")
    print(f"  - Var_ss: 2^{log(Var_ss, 2).n():.4f}")
    print(f"  - Var_fft_ss: 2^{log(Var_fft_ss, 2).n():.4f}")
    print(f"Var_cbs: 2^{log(Var_cbs, 2).n():.4f}")
    print(f"  - Var_cbs_additive: 2^{log(Var_cbs_additive, 2).n():.4f}")
    print(f"  - Var_cbs_amp     : 2^{log(Var_cbs_amp, 2).n():.4f}")
    print(f"Var_Add: 2^{log(Var_Add, 2).n():.4f}")
    print(f"  - Var_Add_gadget: 2^{log(Var_add_gadget, 2).n():.4f}")
    print(f"  - Var_Add_inc   : 2^{log(Var_add_inc, 2).n():.4f}")
    print(f"  - Var_fft_Add   : 2^{log(Var_fft_add, 2).n():.4f}")
    print()
    print(f"(B_cbs, l_cbs): (2^{log(B_cbs, 2)}, {l_cbs})")
    print(f"(B_ksk, l_ksk): (2^{log(B_ksk, 2)}, {l_ksk})")
    print()

    for num_extract in range(1, max_num_extract+1):
        # MV-PBS [CIM19] to extract num_extract bits
        if num_extract == 3:
            Var_Add *= 3
        Var_scaled_in = 2^(2*(log_modulus - num_extract + 1)) * Var_Add # one padding-bit in the MSB is considered (cf. hp_lhe.sage)

        print("-------------------------------------------------------------------------")
        print(f"# extracting bits: {num_extract} (MV-PBS [CIM19] is used after PBSmanyLUT [CLOT21] for LWEtoLev Conversion)")
        print(f"  - Var_Add: 2^{log(Var_Add, 2).n():.4f}")
        print(f"  - Var_scaled_in: 2^{log(Var_scaled_in, 2).n():.4f}")
        print()

        q_prime = q
        delta_in = 2^(64 - num_extract)
        print(f"Delta_in: 2^{log(delta_in, 2)}")
        print("theta:", theta)
        _, min_fp = get_min_fp_pbs(n, q_prime, N, theta, delta_in)
        log_min_fp = log(min_fp, 2).n(1000)
        print(f"Min f.p.: 2^{log_min_fp:.4f}")

        # for log_fp_thrs in [-128, -80, -32]:
        for log_fp_thrs in [-128, -40]:
            if log_min_fp > log_fp_thrs:
                print(f"  - Var_thrs_{-log_fp_thrs:.0f}: impossible")
                print()
            else:
                log_Var_thrs = find_var_thrs(n, q_prime, N, theta, delta_in, log_fp_thrs)
                Var_thrs = 2^log_Var_thrs
                Gamma, fp = get_fp_pbs(n, q_prime, N, theta, delta_in, Var_thrs)
                print(f"  - Var_thrs_{-log_fp_thrs:.0f}: 2^{log_Var_thrs.n():.3f}, Gamma: {Gamma.n():.3f}, fp: 2^{log(fp, 2).n(1000):.4f}")
                if log(fp, 2).n(1000) > log_fp_thrs:
                    print(f"  - Invalid Var_thrs_{-log_fp_thrs:.0f}")
                    break
                max_depth = ((Var_thrs - Var_ks) / Var_scaled_in).n()
                print(f"  - max-depth: {max_depth:.2f}, (max-depth / log_modulus): {max_depth/log_modulus:.2f}")
                print()
        print()
    print()
    print()
