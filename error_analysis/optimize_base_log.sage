load("var.sage")

def optimize_log_B_ks(N, k, log_q, Var_LWE, l_ks):
    q = 2^log_q
    cur = log_q // 2

    # Optimize B_ks
    while cur < log_q:
        Var_cur_gadget = get_var_lwe_ks_gadget(N, k, q, 2^cur, l_ks)
        Var_cur_key = get_var_lwe_ks_key(N, k, q, Var_LWE, 2^cur, l_ks)
        Var_cur = Var_cur_gadget + Var_cur_key

        next = cur + 1 if Var_cur_gadget > Var_cur_key else cur - 1
        Var_next = get_var_lwe_ks(N, k, q, Var_LWE, 2^next, l_ks)

        if Var_next > Var_cur:
            break

        cur = next

    return cur

def optimize_log_B_pbs(N, k, n, log_q, Var_GLWE, l_pbs):
    q = 2^log_q
    cur = log_q // 2

    # Optimize B_pbs by Var_pbs
    while cur < log_q:
        Var_cur_gadget = get_var_pbs_gadget(N, k, n, q, 2^cur, l_pbs)
        Var_cur_key = get_var_pbs_key(N, k, n, q, Var_GLWE, 2^cur, l_pbs)
        Var_cur = Var_cur_gadget + Var_cur_key

        next = cur + 1 if Var_cur_gadget > Var_cur_key else cur - 1
        Var_next = get_var_pbs(N, k, n, q, Var_GLWE, 2^next, l_pbs)

        if Var_next > Var_cur:
            break

        cur = next

    # Optimize B_pbs by Var_pbs + Var_fft_pbs
    Var_fft_cur = get_var_fft_pbs(N, k, n, 2^cur, l_pbs)
    if Var_cur < Var_fft_cur:
        Var_cur_tot = 0
        Var_next_tot = -1
        next = cur

        while Var_cur_tot > Var_next_tot:
            cur = next
            Var_cur_tot = get_var_pbs(N, k, n, q, Var_GLWE, 2^cur, l_pbs)
            Var_cur_tot += get_var_fft_pbs(N, k, n, 2^cur, l_pbs)

            next = cur - 1
            Var_next_tot = get_var_pbs(N, k, n, q, Var_GLWE, 2^next, l_pbs)
            Var_next_tot += get_var_fft_pbs(N, k, n, 2^next, l_pbs)

    return cur

def optimize_log_B_tr_without_split(N, k, log_q, Var_GLWE, l_tr):
    q = 2^log_q
    cur = log_q // 2

    # Optimize B_tr by Var_tr
    while cur < log_q:
        Var_cur_gadget = get_var_glwe_ks_gadget(N, k, q, 2^cur, l_tr)
        Var_cur_key = get_var_glwe_ks_key(N, k, q, Var_GLWE, 2^cur, l_tr)
        Var_cur = get_var_tr(N, k, q, Var_GLWE, 2^cur, l_tr)

        next = cur + 1 if Var_cur_gadget > Var_cur_key else cur - 1
        Var_next = get_var_tr(N, k, q, Var_GLWE, 2^next, l_tr)

        if Var_next > Var_cur:
            break

        cur = next

    # Optimize B_tr by Var_tr + Var_fft_tr
    Var_fft_cur = get_var_fft_tr(N, k, 2^cur, l_tr, 64)
    if Var_cur < Var_fft_cur:
        Var_cur_tot = 0
        Var_next_tot = -1
        next = cur

        while Var_cur_tot > Var_next_tot:
            cur = next
            Var_cur_tot = get_var_tr(N, k, q, Var_GLWE, 2^cur, l_tr)
            Var_cur_tot += get_var_fft_tr(N, k, 2^cur, l_tr, 64)

            next = cur - 1
            Var_next_tot = get_var_tr(N, k, q, Var_GLWE, 2^next, l_tr)
            Var_next_tot += get_var_fft_tr(N, k, 2^next, l_tr, 64)

    return cur, 64

def optimize_log_B_tr(N, k, log_q, Var_GLWE, l_tr, split_limit):
    q = 2^log_q
    cur = log_q // 2

    # Optimize B_tr
    while cur < log_q:
        Var_cur_gadget = get_var_glwe_ks_gadget(N, k, q, 2^cur, l_tr)
        Var_cur_key = get_var_glwe_ks_key(N, k, q, Var_GLWE, 2^cur, l_tr)
        Var_cur = get_var_tr(N, k, q, Var_GLWE, 2^cur, l_tr)

        next = cur + 1 if Var_cur_gadget > Var_cur_key else cur - 1
        Var_next = get_var_tr(N, k, q, Var_GLWE, 2^next, l_tr)

        if Var_next > Var_cur:
            break

        cur = next
    log_B_tr = cur
    B_tr = 2^log_B_tr

    # Optimize b_tr
    cur = log_q // 2
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_tr, l_tr, 2^cur)
    log_fp_split_fft = log(fp_split_fft, 2).n(10000)

    if log_fp_split_fft < split_limit:
        next = cur
        while log_fp_split_fft < split_limit and cur > 0:
            cur = next
            next = cur - 1
            _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_tr, l_tr, 2^next)
            log_fp_split_fft = log(fp_split_fft, 2).n(10000)
    else:
        while log_fp_split_fft > split_limit and cur < log_q:
            next = cur + 1
            cur = next
            _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_tr, l_tr, 2^cur)
            log_fp_split_fft = log(fp_split_fft, 2).n(10000)

    log_b_tr = cur
    b_tr = 2^log_b_tr
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_tr, l_tr, b_tr)
    log_fp_split_fft = log(fp_split_fft, 2)

    if log_fp_split_fft > split_limit:
        log_b_tr = None

    return log_B_tr, log_b_tr

def optimize_log_B_ss(N, k, log_q, Var_GLWE, l_ss):
    q = 2^log_q
    cur = log_q // 2

    # Optimize B_ss by Var_ss
    while cur < log_q:
        Var_cur_gadget = get_var_ss_gadget(N, k, q, 2^cur, l_ss)
        Var_cur_key = get_var_ss_inc(N, k, q^2 * Var_GLWE, 2^cur, l_ss)
        Var_cur = Var_cur_gadget + Var_cur_key

        next = cur + 1 if Var_cur_gadget > Var_cur_key else cur - 1
        Var_next = get_var_ss(N, k, q, q^2 * Var_GLWE, 2^next, l_ss)

        if Var_next > Var_cur:
            break

        cur = next

    # Optimize B_ss by Var_ss + Var_fft_ss
    Var_fft_cur = get_var_fft_ss(N, k, q, 2^cur, l_ss)
    if Var_cur < Var_fft_cur:
        Var_cur_tot = 0
        Var_next_tot = -1
        next = cur

        while Var_cur_tot > Var_next_tot:
            cur = next
            Var_cur_tot = get_var_ss(N, k, q, q^2 * Var_GLWE, 2^cur, l_ss)
            Var_cur_tot += get_var_fft_ss(N, k, q, 2^cur, l_ss)

            next = cur - 1
            Var_next_tot = get_var_ss(N, k, q, q^2 * Var_GLWE, 2^next, l_ss)
            Var_next_tot += get_var_fft_ss(N, k, q, 2^next, l_ss)

    return cur

def optimize_log_B_cbs(N, k, q, Var_cbs, l_cbs):
    q = 2^log_q
    cur = log_q // 2

    # Optimize B_cbs by Var_add
    while cur < log_q:
        Var_add_gadget = get_var_ext_prod_gadget(N, k, q, 2^cur ,l_cbs)
        Var_add_inc = get_var_ext_prod_inc(N, k, Var_cbs, 2^cur, l_cbs)
        Var_cur = Var_add_gadget + Var_add_inc

        next = cur + 1 if Var_add_gadget > Var_add_inc else cur - 1
        Var_next = get_var_ext_prod(N, k, q, Var_cbs, 2^next, l_cbs)

        if Var_next > Var_cur:
            break

        cur = next

    # Optimize B_cbs by Var_add + Var_fft_add
    Var_fft_cur = get_var_fft_ext_prod(N, k, q, 2^cur, l_cbs)
    if Var_cur < Var_fft_cur:
        Var_cur_tot = 0
        Var_next_tot = -1
        next = cur

        while Var_cur_tot > Var_next_tot:
            cur = next
            Var_cur_tot = get_var_ext_prod(N, k, q, Var_cbs, 2^cur, l_cbs)
            Var_cur_tot += get_var_fft_ext_prod(N, k, q, 2^cur, l_cbs)

            next = cur - 1
            Var_next_tot = get_var_ext_prod(N, k, q, Var_cbs, 2^next ,l_cbs)
            Var_next_tot += get_var_fft_ext_prod(N, k, q, 2^next ,l_cbs)
    return cur
