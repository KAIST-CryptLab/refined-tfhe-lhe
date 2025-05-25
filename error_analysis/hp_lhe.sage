load("var.sage")
load("param.sage")

q = 2^64
N = 2048
k = 1
Var_GLWE = stddev_2048^2
k_large = 2
Var_large_GLWE = stddev_4096^2


param_list = [
    wopbs_2_2,
    wopbs_3_3,
    wopbs_4_4,
]

for param in param_list:
    name = param[0]
    (n, Var_LWE) = param[1]
    (B_pbs, l_pbs) = param[2]
    (B_cbs, l_cbs) = param[3]
    (B_ksk, l_ksk) = param[4]
    theta = param[5]
    log_modulus = param[6]
    max_num_extract = param[7]

    print(f"========================= {name} =========================")
    print(f"n: {n}, N: {N}, k: {k}, B_pbs: 2^{log(B_pbs, 2)}, l_pbs: {l_pbs}\n")

    Var_PBS = get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
    Var_FFT = get_var_fft_pbs(N, k, n, B_pbs, l_pbs)
    Var_KS = get_var_lwe_ks(N, k, q, Var_LWE, B_ksk, l_ksk)

    print(f"Var_PBS: 2^{log(Var_PBS, 2).n():.4f}")
    print(f"Var_FFT: 2^{log(Var_FFT, 2).n():.4f}")
    print(f"Var_KS: 2^{log(Var_KS, 2).n():.4f}")
    print()
    print(f"(B_cbs, l_cbs): (2^{log(B_cbs, 2)}, {l_cbs})")
    print(f"(B_ksk, l_ksk): (2^{log(B_ksk, 2)}, {l_ksk})")
    print()

    for num_extract in range(1, max_num_extract+1):
        Var_Add = get_var_ext_prod(N, k, q, Var_PBS + Var_FFT, B_cbs, l_cbs)
        # MV-PBS [CIM19] to extract num_extract bits
        if num_extract == 3:
            Var_Add *= 3
        Var_scaled_in = 2^(2*(log_modulus - num_extract)) * Var_Add

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

        for log_fp_thrs in [-40]:
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
                max_depth = ((Var_thrs - Var_KS) / Var_scaled_in).n()
                print(f"  - max-depth: {max_depth:.2f}, (max-depth / log_modulus): {max_depth/log_modulus:.2f}")
                print()
        print()
    print()
    print()




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
    print(f"n: {n}, N: {N}, k: {k}, B_pbs: 2^{log(B_pbs, 2)}, l_pbs: {l_pbs}, B_ks: 2^{log(B_ksk, 2)}, l_ks: {l_ksk}")
    print(f"B_tr: 2^{log(B_tr, 2)}, l_tr: {l_tr}, b_tr: 2^{log(b_tr, 2)}, B_ss: 2^{log(B_ss, 2)}, l_ss: {l_ss}, B_cbs: 2^{log(B_cbs, 2)}, l_cbs: {l_cbs}\n")

    Var_pbs = get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
    Var_fft_pbs = get_var_fft_pbs(N, k, n, B_pbs, l_pbs)
    Var_pbs_tot = Var_pbs + Var_fft_pbs
    Var_ks = get_var_lwe_ks(N, k, q, Var_LWE, B_ksk, l_ksk)

    Var_tr = get_var_tr(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_auto_gadget = get_var_glwe_ks_gadget(N, k, q, B_tr, l_tr)
    Var_auto_key = get_var_glwe_ks_key(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_fft_tr = get_var_fft_tr(N, k, B_tr, l_tr, b_tr)
    Var_tr_tot = Var_tr + Var_fft_tr

    Var_split_fft_tr_upper = get_var_fft_glwe_ks(N, k, B_tr, l_tr, q / b_tr)
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_tr, l_tr, b_tr)
    log_fp_split_fft = log(fp_split_fft, 2).n(10000)

    Var_ss = get_var_ss(N, k, q, q^2 * Var_GLWE, B_ss, l_ss)
    Var_ss_gadget = get_var_ss_gadget(N, k, q, B_ss, l_ss)
    Var_ss_inc = get_var_ss_inc(N, k, q^2 * Var_GLWE, B_ss, l_ss)
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
    print(f"  - F.P. of split fft: 2^{log_fp_split_fft:.4f} (stddev_upper: 2^{log(Var_split_fft_tr_upper, 2).n() / 2:.4f})")
    print(f"Var_ss_tot: 2^{log(Var_ss_tot, 2).n():.4f}")
    print(f"  - Var_ss: 2^{log(Var_ss, 2).n():.4f}")
    print(f"    - Var_ss_gadget: 2^{log(Var_ss_gadget, 2).n():.4f}")
    print(f"    - Var_ss_inc   : 2^{log(Var_ss_inc, 2).n():.4f}")
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
        Var_scaled_in = 2^(2*(log_modulus - num_extract)) * Var_Add

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

        for log_fp_thrs in [-40]:
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



param_list = [
    improved_wopbs_3_3,
    improved_wopbs_4_4,
]

for param in param_list:
    name = param[0]
    (n, Var_LWE) = param[1]
    (B_pbs, l_pbs) = param[2]
    (B_tr, l_tr, b_tr) = param[3]
    (B_ss, l_ss) = param[4]
    (B_to_large, l_to_large, b_to_large) = param[5]
    (B_from_large, l_from_large, b_from_large) = param[6]
    (B_cbs, l_cbs) = param[7]
    (B_ksk, l_ksk) = param[8]
    theta = param[9]
    log_modulus = param[10]
    max_num_extract = param[11]

    print(f"========================= {name} =========================")
    print(f"n: {n}, N: {N}, k: {k}, B_pbs: 2^{log(B_pbs, 2)}, l_pbs: {l_pbs}\n")
    print(f"B_to_large: 2^{log(B_to_large, 2)}, l_to_large: {l_to_large}, b_to_large: 2^{log(b_to_large, 2)}")
    print(f"B_tr: 2^{log(B_tr, 2)}, l_tr: {l_tr}, b_tr: 2^{log(b_tr, 2)}")
    print(f"B_from_large: 2^{log(B_from_large, 2)}, l_from_large: {l_from_large}, b_from_large: 2^{log(b_from_large, 2)}")
    print(f"B_ss: 2^{log(B_ss, 2)}, l_ss: {l_ss}, B_cbs: 2^{log(B_cbs, 2)}, l_cbs: {l_cbs}\n")

    Var_pbs = get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
    Var_fft_pbs = get_var_fft_pbs(N, k, n, B_pbs, l_pbs)
    Var_pbs_tot = Var_pbs + Var_fft_pbs
    Var_ks = get_var_lwe_ks(N, k, q, Var_LWE, B_ksk, l_ksk)

    Var_to_large = get_var_glwe_ks(N, k, q, Var_large_GLWE, B_to_large, l_to_large)
    Var_fft_to_large = get_var_fft_glwe_ks(N, k, B_to_large, l_to_large, b_to_large)
    Var_to_large_gadget = get_var_glwe_ks_gadget(N, k, q, B_to_large, l_to_large)
    Var_to_large_key = get_var_glwe_ks_key(N, k, q, Var_large_GLWE, B_to_large, l_to_large)
    Var_to_large_tot = Var_to_large + Var_fft_to_large

    Var_split_fft_upper_to_large = get_var_fft_glwe_ks(N, k, B_to_large, l_to_large, q / b_to_large)
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_to_large, l_to_large, b_to_large)
    log_fp_split_fft_to_large = log(fp_split_fft, 2).n(10000)

    Var_tr = get_var_tr(N, k_large, q, Var_large_GLWE, B_tr, l_tr)
    Var_auto_gadget = get_var_glwe_ks_gadget(N, k_large, q, B_tr, l_tr)
    Var_auto_key = get_var_glwe_ks_key(N, k_large, q, Var_large_GLWE, B_tr, l_tr)
    Var_fft_tr = get_var_fft_tr(N, k, B_tr, l_tr, b_tr)
    Var_tr_tot = Var_tr + Var_fft_tr

    Var_split_fft_tr_upper = get_var_fft_glwe_ks(N, k_large, B_tr, l_tr, q / b_tr)
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k_large, q, B_tr, l_tr, b_tr)
    log_fp_split_fft_tr = log(fp_split_fft, 2).n(10000)

    Var_from_large = get_var_glwe_ks(N, k_large, q, Var_GLWE, B_from_large, l_from_large)
    Var_fft_from_large = get_var_fft_glwe_ks(N, k_large, B_from_large, l_from_large, b_from_large)
    Var_from_large_gadget = get_var_glwe_ks_gadget(N, k_large, q, B_from_large, l_from_large)
    Var_from_large_key = get_var_glwe_ks_key(N, k_large, q, Var_GLWE, B_from_large, l_from_large)
    Var_from_large_tot = Var_from_large + Var_fft_from_large

    Var_split_fft_upper_from_large = get_var_fft_glwe_ks(N, k_large, B_from_large, l_from_large, q / b_from_large)
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k_large, q, B_from_large, l_from_large, b_from_large)
    log_fp_split_fft_from_large = log(fp_split_fft, 2).n(10000)

    Var_ss = get_var_ss(N, k, q, q^2 * Var_GLWE, B_ss, l_ss)
    Var_fft_ss = get_var_fft_ext_prod(N, k, q, B_ss, l_ss)
    Var_ss_tot = Var_ss + Var_fft_ss

    Var_cbs = Var_pbs_tot + Var_to_large_tot + Var_ss_tot + (N/2) * (Var_tr_tot + Var_from_large_tot)
    Var_cbs_additive = Var_pbs_tot + Var_to_large_tot + Var_ss_tot
    Var_cbs_amp = (N/2) * (Var_tr_tot + Var_from_large_tot)

    Var_Add = get_var_ext_prod(N, k, q, Var_cbs, B_cbs, l_cbs) + get_var_fft_ext_prod(N, k, q, B_cbs, l_cbs)
    Var_add_gadget = get_var_ext_prod_gadget(N, k, q, B_cbs, l_cbs)
    Var_add_inc = get_var_ext_prod_inc(N, k, Var_cbs, B_cbs, l_cbs)
    Var_fft_add = get_var_fft_ext_prod(N, k, q, B_cbs, l_cbs)

    print(f"Var_ks: 2^{log(Var_ks, 2).n():.4f}")
    print(f"Var_pbs_tot: 2^{log(Var_pbs_tot, 2).n():.4f}")
    print(f"  - Var_pbs: 2^{log(Var_pbs, 2).n():.4f}")
    print(f"  - Var_fft_pbs: 2^{log(Var_fft_pbs, 2).n():.4f}")
    print(f"Var_to_large_tot : 2^{log(Var_to_large_tot, 2).n():.4f}")
    print(f"  - Var_to_large: 2^{log(Var_to_large, 2).n():.4f}")
    print(f"    - Var_to_large_gadget: 2^{log(Var_to_large_gadget).n():.4f}")
    print(f"    - Var_to_large_key   : 2^{log(Var_to_large_key).n():.4f}")
    print(f"  - Var_fft_to_large: 2^{log(Var_fft_to_large, 2).n():.4f}")
    print(f"  - F.P. of split fft: 2^{log_fp_split_fft_to_large:.4f} (stddev_upper: 2^{log(Var_split_fft_upper_to_large, 2).n() / 2:.4f})")
    print(f"Var_tr_tot : 2^{log(Var_tr_tot, 2).n():.4f}")
    print(f"  - Var_tr: 2^{log(Var_tr, 2).n():.4f}")
    print(f"     - Var_auto_gadget: 2^{log(Var_auto_gadget, 2).n():.4f}")
    print(f"     - Var_auto_key: 2^{log(Var_auto_key, 2).n():.4f}")
    print(f"  - Var_fft_tr: 2^{log(Var_fft_tr, 2).n():.4f}")
    print(f"  - F.P. of split fft: 2^{log_fp_split_fft_tr:.4f} (stddev_upper: 2^{log(Var_split_fft_tr_upper, 2).n() / 2:.4f})")
    print(f"Var_from_large_tot : 2^{log(Var_from_large_tot, 2).n():.4f}")
    print(f"  - Var_from_large: 2^{log(Var_from_large, 2).n():.4f}")
    print(f"    - Var_from_large_gadget: 2^{log(Var_from_large_gadget).n():.4f}")
    print(f"    - Var_from_large_key   : 2^{log(Var_from_large_key).n():.4f}")
    print(f"  - Var_fft_from_large: 2^{log(Var_fft_from_large, 2).n():.4f}")
    print(f"  - F.P. of split fft: 2^{log_fp_split_fft_from_large:.4f} (stddev_upper: 2^{log(Var_split_fft_upper_from_large, 2).n() / 2:.4f})")
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
        Var_scaled_in = 2^(2*(log_modulus - num_extract)) * Var_Add

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

        for log_fp_thrs in [-40]:
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