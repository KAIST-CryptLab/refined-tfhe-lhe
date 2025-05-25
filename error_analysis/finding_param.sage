import argparse
from prettytable import PrettyTable

load("var.sage")
load("param.sage")
load("optimize_base_log.sage")

parser = argparse.ArgumentParser(prog='sage finding_param.sage', description='finding appropriate decomposition base logs under the given TFHE parameters and decomposition levels')
parser.add_argument('-n', nargs=1, type=int, default=[636], help='LWE dimension n, default to 636')
parser.add_argument('-lwe', nargs=1, type=float, default=[stddev_636], help='LWE std dev, default to 9.25119974676756e-5 that corresponds to default n = 636')
parser.add_argument('-k', nargs=1, type=int, default=[1], help='GLWE dimension k, default to 1')
parser.add_argument('-N', nargs=1, type=int, default=[2048], help='polynomial size N, default to 2048')
parser.add_argument('-glwe', nargs=1, type=float, default=[stddev_2048], help='GLWE std dev, default to 9.25119974676756e-16 that corresponds to default (N, k) = (2048, 1)')
parser.add_argument('-log_q', nargs=1, type=int, default=[64], help='log q, default to 64')
parser.add_argument('-t', nargs=1, type=int, default=[2], help='vartheta, default to 2')
parser.add_argument('-l', nargs=5, type=int, help='decomposition levels: [ks, pbs, tr, ss, cbs]')
parser.add_argument('-B', nargs=6, type=int, help='log of decomposition bases: [pbs, ks, tr, split, ss, cbs]')
parser.add_argument('-sp', nargs=1, type=int, default=[-256], help='log of f.p. of split fft, default to 256')
parser.add_argument('-thrs', nargs=1, type=int, default=[-40], help='log of threshold f.p., default to -40]')
parser.add_argument('-ns', action="store_true", help='do not use split FFT for HomTrace')

if __name__ == '__main__':
    args = parser.parse_args()
    n = args.n[0]
    sigma_lwe = args.lwe[0]
    k = args.k[0]
    N = args.N[0]
    sigma_glwe = args.glwe[0]
    log_q = args.log_q[0]
    q = 2^log_q
    theta = args.t[0]
    split_limit = args.sp[0]
    is_opt = args.B is None
    log_fp_thrs_list = args.thrs
    is_no_split_fft = True if args.ns else False

    print(f"LWE Dimension (-n):\t{n}")
    print(f"LWE Std. Dev (-lwe):\t{sigma_lwe:.5e}")
    print(f"GLWE Dimension (-k):\t{k}")
    print(f"Polynomial Size (-N):\t{N}")
    print(f"GLWE Std. Dev (-glwe):\t{sigma_glwe:.5e}")
    print(f"q (-log_q):\t\t2^{log_q}")
    print(f"theta (-t):\t\t{theta}")
    print()

    if args.l is None or len(args.l) != 5:
        print("Give 5 gadget lengths by the -l flag: -l l_ks l_pbs l_tr l_ss l_cbs")
        exit()
    else:
        [l_ks, l_pbs, l_tr, l_ss, l_cbs] = args.l

    Var_LWE = sigma_lwe^2
    Var_GLWE = sigma_glwe^2

    if is_opt:
        log_B_ks = optimize_log_B_ks(N, k, log_q, Var_LWE, l_ks)
        B_ks = 2^log_B_ks

        log_B_pbs = optimize_log_B_pbs(N, k, n, log_q, Var_GLWE, l_pbs)
        B_pbs = 2^log_B_pbs

        if is_no_split_fft:
            log_B_tr, log_b_tr = optimize_log_B_tr_without_split(N, k, log_q, Var_GLWE, l_tr)
        else:
            log_B_tr, log_b_tr = optimize_log_B_tr(N, k, log_q, Var_GLWE, l_tr, split_limit)
        B_tr = 2^log_B_tr
        b_tr = 2^log_b_tr

        log_B_ss = optimize_log_B_ss(N, k, log_q, Var_GLWE, l_ss)
        B_ss = 2^log_B_ss

        Var_pbs_tot = get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
        Var_pbs_tot += get_var_fft_pbs(N, k, n, B_pbs, l_pbs)
        Var_tr_tot = get_var_tr(N, k, q, Var_GLWE, B_tr, l_tr)
        Var_tr_tot += get_var_fft_tr(N, k, B_tr, l_tr, b_tr)
        Var_ss_tot = get_var_ss(N, k, q, q^2 * Var_GLWE, B_ss, l_ss)
        Var_ss_tot += get_var_fft_ss(N, k, q, B_ss, l_ss)

        Var_cbs = (Var_pbs_tot + Var_ss_tot) + (N/2) * Var_tr_tot
        log_B_cbs = optimize_log_B_cbs(N, k, q, Var_cbs, l_cbs)
        B_cbs = 2^log_B_cbs
    else:
        [log_B_ks, log_B_pbs, log_B_tr, log_b_tr, log_B_ss, log_B_cbs] = args.B
        [B_ks, B_pbs, B_tr, b_tr, B_ss, B_cbs] = [2^log_B_ks, 2^log_B_pbs, 2^log_B_tr, 2^log_b_tr, 2^log_B_ss, 2^log_B_cbs]

    tab = PrettyTable(['', 'l', 'B', 'b'])
    tab.add_row(['LWE KS', l_ks, f'2^{log_B_ks}', ''])
    tab.add_row(['PBS', l_pbs, f'2^{log_B_pbs}', ''])
    tab.add_row(['Trace', l_tr, f'2^{log_B_tr}', f'2^{log_b_tr}'])
    tab.add_row(['SS', l_ss, f'2^{log_B_ss}', ''])
    tab.add_row(['CBS', l_cbs, f'2^{log_B_cbs}', ''])
    print(tab)
    print()

    Var_lwe_ks = get_var_lwe_ks(N, k, q, Var_LWE, B_ks, l_ks)
    print(f"Var_lwe_ks:\t\t2^{log(Var_lwe_ks, 2).n():.4f}")

    Var_pbs = get_var_pbs(N, k, n, q, Var_GLWE, B_pbs, l_pbs)
    Var_fft_pbs = get_var_fft_pbs(N, k, n, B_pbs, l_pbs)
    Var_pbs_tot = Var_pbs + Var_fft_pbs

    print(f"Var_pbs_tot:\t\t2^{log(Var_pbs_tot, 2).n():.4f}")
    print(f"  - Var_pbs:\t\t2^{log(Var_pbs, 2).n():.4f}")
    print(f"  - Var_fft_pbs:\t2^{log(Var_fft_pbs, 2).n():.4f}")

    Var_tr = get_var_tr(N, k, q, Var_GLWE, B_tr, l_tr)
    Var_fft_tr = get_var_fft_tr(N, k, B_tr, l_tr, b_tr)
    Var_tr_tot = Var_tr + Var_fft_tr
    _, fp_split_fft = get_fp_split_fft_glwe_ks(N, k, q, B_tr, l_tr, b_tr)

    print(f"Var_tr_tot:\t\t2^{log(Var_tr_tot, 2).n():.4f}")
    print(f"  - Var_tr:\t\t2^{log(Var_tr, 2).n():.4f}")
    print(f"  - Var_fft_tr:\t\t2^{log(Var_fft_tr, 2).n():.4f}")
    print(f"  - F.P. of split FFT:\t2^{log(fp_split_fft, 2).n(10000):.4f}")

    Var_ss = get_var_ss(N, k, q, q^2 * Var_GLWE, B_ss, l_ss)
    Var_fft_ss = get_var_fft_ss(N, k, q, B_ss, l_ss)
    Var_ss_tot = Var_ss + Var_fft_ss

    print(f"Var_ss_tot:\t\t2^{log(Var_ss_tot, 2).n():.4f}")
    print(f"  - Var_ss:\t\t2^{log(Var_ss, 2).n():.4f}")
    print(f"  - Var_fft_ss:\t\t2^{log(Var_fft_ss, 2).n():.4f}")

    Var_cbs = (Var_pbs_tot + Var_ss_tot) + (N/2) * Var_tr_tot
    Var_add = get_var_ext_prod(N, k, q, Var_cbs, B_cbs, l_cbs)
    Var_fft_add = get_var_fft_ext_prod(N, k, q, B_cbs, l_cbs)
    Var_add_tot = Var_add + Var_fft_add

    print(f"Var_add_tot:\t\t2^{log(Var_add_tot, 2).n():.4f}")
    print(f"  - Var_cbs:\t\t2^{log(Var_cbs, 2).n():.4f}")
    print(f"  - Var_add:\t\t2^{log(Var_add, 2).n():.4f}")
    print(f"  - Var_fft_add:\t2^{log(Var_fft_add, 2).n():.4f}")

    print(f"max-depth for")
    for log_fp_thrs in log_fp_thrs_list:
        delta_in = q / 2
        log_var_thrs = find_var_thrs(n, q, N, theta, delta_in, log_fp_thrs)
        Var_thrs = 2^log_var_thrs
        max_depth = ((Var_thrs - Var_lwe_ks) / Var_add_tot).n()
        print(f"  - F.P. of 2^{log_fp_thrs}:\t{max_depth:.4f}")
    print()
