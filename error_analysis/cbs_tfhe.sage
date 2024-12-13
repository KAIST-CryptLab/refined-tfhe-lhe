# -------- PBS -------- #
def get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs):
    Var_PBS = 0
    Var_PBS += get_var_pbs_gadget(N, k, n, q, B_pbs, l_pbs)
    Var_PBS += get_var_pbs_key(N, k, n, q, Var_GLWE, B_pbs, l_pbs)

    return Var_PBS

def get_var_pbs_gadget(N, k, n, q, B_pbs, l_pbs):
    Bp_2l_pbs = B_pbs^(2*l_pbs)

    Var_gadget = 0
    Var_gadget += n*(q^2-Bp_2l_pbs)/(24*Bp_2l_pbs) * (1+k*N/2)
    Var_gadget += (n*k*N)/32
    Var_gadget += (n/16)*(1-k*N/2)^2

    return Var_gadget

def get_var_pbs_key(N, k, n, q, Var_GLWE, B_pbs, l_pbs):
    B2_12_pbs = (B_pbs^2 + 2)/12
    Var_BSK = Var_GLWE * q^2

    return n*l_pbs*(k+1)*N*B2_12_pbs*Var_BSK

def get_var_fft_pbs(N, k, n, B_pbs, l_pbs):
    return n * 2^(22 - 2.6) * l_pbs * B_pbs^2 * N^2 * (k+1)

def get_fp_pbs(n, q_prime, N, theta, delta_in, Var_in):
    w = 2*N/2^theta
    Gamma = (delta_in / 2) * (Var_in + q_prime^2/(12*w^2) - 1/12 + n*q_prime^2/(24*w^2) + n/48)^(-1/2)
    sq2 = 2^(1/2)
    fp = 1 - erf(Gamma/sq2)

    return Gamma, fp

def get_min_fp_pbs(n, q_prime, N, theta, delta_in):
    w = 2*N/2^theta
    Gamma = (delta_in / 2) * (q_prime^2/(12*w^2) - 1/12 + n*q_prime^2/(24*w^2) + n/48)^(-1/2)
    sq2 = 2^(1/2)
    fp = 1 - erf(Gamma/sq2)

    return Gamma, fp

def find_var_thrs(n, q_prime, N, theta, delta_in, log_fp_thrs, prec=3):
    def get_log_fp(var_in):
        _, fp = get_fp_pbs(n, q_prime, N, theta, delta_in, var_in)
        return log(fp, 2).n(1000)

    _, min_fp = get_min_fp_pbs(n, q_prime, N, theta, delta_in)
    min_log_fp = log(min_fp, 2).n(1000)

    if log_fp_thrs < min_log_fp:
        return None

    int_lower = 0
    int_upper = 128
    pivot = 64
    log_fp = get_log_fp(2^pivot)
    while int_lower != int_upper - 1:
        if log_fp < log_fp_thrs:
            int_lower = pivot
        else:
            int_upper = pivot
        pivot = (int_lower + int_upper) // 2
        log_fp = get_log_fp(2^pivot)

    int_part = pivot
    frac_lower = 0
    frac_upper = (10^prec) - 1
    pivot = (frac_lower + frac_upper) // 2
    log_fp = get_log_fp(2^(int_part + pivot / 10^prec))
    while frac_lower != frac_upper - 1:
        if log_fp < log_fp_thrs:
            frac_lower = pivot
        else:
            frac_upper = pivot
        pivot = (frac_lower + frac_upper) // 2
        log_fp = get_log_fp(2^(int_part + pivot / 10^prec))

    return int_part + pivot / 10^prec

# -------- External Product -------- #
def get_var_ext_prod(N, k, q, Var_in, B_ep, l_ep):
    Var_ep = 0
    Var_ep += get_var_ext_prod_gadget(N, k, q, B_ep, l_ep)
    Var_ep += get_var_ext_prod_inc(N, k, Var_in, B_ep, l_ep)

    return Var_ep

def get_var_ext_prod_gadget(N, k, q, B_ep, l_ep):
    Bp_2l_ep = B_ep^(2*l_ep)
    return (1 + k*N)*((q^2 - Bp_2l_ep)/(24 * Bp_2l_ep) + 1/16)

def get_var_ext_prod_inc(N, k, Var_in, B_ep, l_ep):
    B2_12_ep = (B_ep^2 + 2)/12
    return (k+1)*l_ep*N * B2_12_ep * Var_in

def get_var_fft_ext_prod(N, k, q, B_ep, l_ep):
    return 2^(-2*53-2.6) * (k+1) * l_ep * B_ep^2 * q^2 * N^2

# -------- LWE KS -------- #
def get_var_lwe_ks(N, k, q, Var_LWE, B_ksk, l_ksk):
    Var_KS = 0
    Var_KS += get_var_lwe_ks_gadget(N, k, q, B_ksk, l_ksk)
    Var_KS += get_var_lwe_ks_key(N, k, q, Var_LWE, B_ksk, l_ksk)

    return Var_KS

def get_var_lwe_ks_gadget(N, k, q, B_ksk, l_ksk):
    Bp_2l_ksk = B_ksk^(2*l_ksk)

    return k*N*((q^2-Bp_2l_ksk)/(24*Bp_2l_ksk) + 1/16)

def get_var_lwe_ks_key(N, k, q, Var_LWE, B_ksk, l_ksk):
    B2_12_ksk = B_ksk^2 / 12
    Var_KSK = q^2 * Var_LWE

    return k*N*l_ksk*Var_KSK * (B2_12_ksk + 1/6)

# -------- GLWE KS -------- #
def get_var_glwe_ks(N, k_src, q, Var_dst, B_ksk, l_ksk):
    Var_KS = 0
    Var_KS += get_var_glwe_ks_gadget(N, k_src, q, B_ksk, l_ksk)
    Var_KS += get_var_glwe_ks_key(N, k_src, q, Var_dst, B_ksk, l_ksk)

    return Var_KS

def get_var_glwe_ks_gadget(N, k_src, q, B_ksk, l_ksk):
    return k_src * N * ((q^2 - B_ksk^(2*l_ksk)) / (24 * B_ksk^(2*l_ksk)) + 1/16)

def get_var_glwe_ks_key(N, k_src, q, Var_dst, B_ksk, l_ksk):
    Var_KSK = Var_dst * q^2
    return k_src * N * l_ksk * Var_KSK * (B_ksk^2 + 2) / 12

def get_var_fft_glwe_ks(N, k, B_ksk, l_ksk, b_fft):
    return 2^(-2*53-2.6) * k * l_ksk * B_ksk^2 * b_fft^2 * N^2

# -------- HomTrace -------- #
def get_var_tr(N, k, q, Var_ak, B_auto, l_auto):
    Var_auto = get_var_glwe_ks(N, k, q, Var_ak, B_auto, l_auto)
    Var_tr = (N^2 - 1)/3 *  Var_auto

    return Var_tr

def get_var_fft_tr(N, k, B_ksk, l_ksk, b_fft):
    return (N^2 - 1)/3 * get_var_fft_glwe_ks(N, k, B_ksk, l_ksk, b_fft)

def get_fp_split_fft_glwe_ks(N, k, q, B_ks, l_ks, b_fft):
    Var_fft_upper = get_var_fft_glwe_ks(N, k, B_ks, l_ks, q / b_fft)
    Gamma = 1/(2 * Var_fft_upper^(1/2))
    sq2 = 2^(1/2)
    fp = 1 - erf(Gamma/sq2)

    return Gamma, fp

# -------- SchemeSwitch -------- #
def get_var_ss(N, k, q, Var_in, B_ss, l_ss):
    Var_ss = 0
    Var_ss += get_var_ss_gadget(N, k, q, B_ss, l_ss)
    Var_ss += get_var_ss_inc(N, k, Var_in, B_ss, l_ss)

    return Var_ss

def get_var_ss_gadget(N, k, q, B_ss, l_ss):
    return get_var_ext_prod_gadget(N, k, q, B_ss, l_ss) * N/2

def get_var_ss_inc(N, k, Var_in, B_ss, l_ss):
    return get_var_ext_prod_inc(N, k, Var_in, B_ss, l_ss)

def get_var_fft_ss(N, k, q, B_ss, l_ss):
    return get_var_fft_ext_prod(N, k, q, B_ss, l_ss)

# load('var.sage')

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
    True,
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
    True,
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
    True,
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


