load("var.sage")
load("param.sage")

n = 636
Var_LWE = stddev_636^2 # 130.7-bit security
B_ksk = 2^2
l_ksk = 5
N = 2048
k = 1
Var_GLWE = stddev_2048^2
theta = 2
q = 2^64
delta_in = 2^63

print(f"n = {n}, Var_LWE = 2^{log(Var_LWE, 2).n():.4f}, N = {N}, k = {k}, Var_GLWE = 2^{log(Var_GLWE, 2).n():.4f}, q = 2^{log(q, 2)}, theta = {theta}, B_ks = 2^{log(B_ksk, 2)}, l_ks = {l_ksk}")
log_fp_thrs_list = [-40]
for log_fp_thrs in log_fp_thrs_list:
    log_var_thrs = find_var_thrs(n, q, N, theta, delta_in, log_fp_thrs)
    print(f"  - For F.P. bound of 2^{log_fp_thrs}, var_thrs = 2^{log_var_thrs.n():.4f}")

Var_lwe_ks = get_var_lwe_ks(N, k, q, Var_LWE, B_ksk, l_ksk)
Var_lwe_ks_gadget = get_var_lwe_ks_gadget(N, k, q, B_ksk, l_ksk)
Var_lwe_ks_key = get_var_lwe_ks_key(N, k, q, Var_LWE, B_ksk, l_ksk)
print(f"Var_lwe_ks: 2^{log(Var_lwe_ks, 2).n():.4f}")
print(f"  - Var_lwe_ks_gadget: 2^{log(Var_lwe_ks_gadget, 2).n():.4f}")
print(f"  - Var_lwe_ks_key   : 2^{log(Var_lwe_ks_key, 2).n():.4f}")
print()


param_list = [
    cmux1,
    cmux2,
    cmux3,
]

for param in param_list:
    name = param[0]
    (B_pbs, l_pbs) = param[1]
    (B_tr, l_tr, b_tr) = param[2]
    (B_ss, l_ss) = param[3]
    (B_cbs, l_cbs) = param[4]

    print(f"======== {name} ========")
    print(f"B_pbs = 2^{log(B_pbs, 2)}, l_pbs = {l_pbs}, B_tr = 2^{log(B_tr, 2)}, l_tr = {l_tr}, b_tr = 2^{log(b_tr, 2)}, B_ss = 2^{log(B_ss, 2)}, l_ss = {l_ss}, B_cbs = 2^{log(B_cbs, 2)}, l_cbs = {l_cbs}")
    print()

    Var_pbs = get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
    Var_pbs_gadget = get_var_pbs_gadget(N, k, n, q, B_pbs, l_pbs)
    Var_pbs_key = get_var_pbs_key(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
    Var_fft_pbs = get_var_fft_pbs(N, k, n, B_pbs, l_pbs)
    Var_pbs_tot = Var_pbs + Var_fft_pbs

    print(f"Var_pbs_tot: 2^{log(Var_pbs_tot, 2).n():.4f}")
    print(f"  - Var_pbs: 2^{log(Var_pbs, 2).n():.4f}")
    print(f"    - Var_pbs_gadget: 2^{log(Var_pbs_gadget, 2).n():.4f}")
    print(f"    - Var_pbs_key   : 2^{log(Var_pbs_key, 2).n():.4f}")
    print(f"  - Var_fft_pbs: 2^{log(Var_fft_pbs, 2).n():.4f}")
    print()

    Var_tr = get_var_tr(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_auto_gadget = get_var_glwe_ks_gadget(N, k, q, B_tr, l_tr)
    Var_auto_key = get_var_glwe_ks_key(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_fft_tr = get_var_fft_tr(N, k, B_tr, l_tr, b_tr)
    Var_tr_tot = Var_tr + Var_fft_tr
    Var_split_fft_upper = get_var_fft_glwe_ks(N, k, B_tr, l_tr, q / b_tr)
    Gamma, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_tr, l_tr, b_tr)

    print(f"Var_tr_tot: 2^{log(Var_tr_tot, 2).n():.4f}")
    print(f"  - Var_tr:     2^{log(Var_tr, 2).n():.4f}")
    print(f"    - Var_auto_gadget: 2^{log(Var_auto_gadget, 2).n():.4f}")
    print(f"    - Var_auto_key   : 2^{log(Var_auto_key, 2).n():.4f}")
    print(f"  - Var_fft_tr: 2^{log(Var_fft_tr, 2).n():.4f}")
    print(f"F.P. of split FFT for Tr: stddev_upper = 2^{log(Var_split_fft_upper, 2) / 2:.4f}, Gamma = {Gamma:.4f}, fp = 2^{log(fp_split_fft, 2).n(10000):.4f}")
    print()

    Var_ss = get_var_ss(N, k, q, q^2 * Var_GLWE, B_ss, l_ss)
    Var_ss_gadget = get_var_ss_gadget(N, k, q, B_ss, l_ss)
    Var_ss_key = get_var_ss_inc(N, k, q^2 * Var_GLWE, B_ss, l_ss)
    Var_fft_ss = get_var_fft_ext_prod(N, k, q, B_ss, l_ss)
    Var_ss_tot = Var_ss + Var_fft_ss

    print(f"Var_ss_tot: 2^{log(Var_ss_tot, 2).n():.4f}")
    print(f"  - Var_ss: 2^{log(Var_ss, 2).n():.4f}")
    print(f"    - Var_ss_gadget: 2^{log(Var_ss_gadget, 2).n():.4f}")
    print(f"    - Var_ss_key   : 2^{log(Var_ss_key, 2).n():.4f}")
    print(f"  - Var_fft_ss: 2^{log(Var_fft_ss, 2).n():.4f}")
    print()

    Var_cbs = (Var_pbs + Var_fft_pbs + Var_ss + Var_fft_ss) + (N/2) * (Var_tr + Var_fft_tr)
    Var_cbs_additive = Var_pbs_tot + Var_ss_tot
    Var_cbs_amp = (N/2) * Var_tr_tot

    print(f"Var_cbs: 2^{log(Var_cbs, 2).n():.4f}")
    print(f"  - Var_pbs + Var_ss (w/ fft err): 2^{log(Var_cbs_additive, 2).n():.4f}")
    print(f"  - (N/2) * Var_tr   (w/ fft err): 2^{log(Var_cbs_amp, 2).n():.4f}")
    print()

    Var_add = get_var_ext_prod(N, k, q, Var_cbs, B_cbs, l_cbs)
    Var_add_gadget = get_var_ext_prod_gadget(N, k, q, B_cbs, l_cbs)
    Var_add_inc = get_var_ext_prod_inc(N, k, Var_cbs, B_cbs, l_cbs)
    Var_fft_add = get_var_fft_ext_prod(N, k, q, B_cbs, l_cbs)
    Var_add_tot = Var_add + Var_fft_add

    print(f"Var_add_tot: 2^{log(Var_add_tot, 2).n():.4f}")
    print(f"  - Var_add: 2^{log(Var_add, 2).n():.4f}")
    print(f"    - Var_add_gadget: 2^{log(Var_add_gadget, 2).n()}")
    print(f"    - Var_add_inc   : 2^{log(Var_add_inc, 2).n()}")
    print(f"  - Var_fft_add: 2^{log(Var_fft_add, 2).n():.4f}")
    print()

    print(f"max-depth for")
    for log_fp_thrs in log_fp_thrs_list:
        log_var_thrs = find_var_thrs(n, q, N, theta, delta_in, log_fp_thrs)
        Var_thrs = 2^log_var_thrs
        max_depth = ((Var_thrs - Var_lwe_ks) / Var_add).n()
        print(f"  - F.P. of 2^{log_fp_thrs}: {max_depth}")
    print()

