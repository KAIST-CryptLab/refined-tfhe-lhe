stddev_653 = 6.772274609789095e-05 # 130.6 bit security
stddev_636 = 9.25119974676756e-5 # 130.7 bit security
stddev_768 = 8.763872947670246e-06 # 130.1 bit security
stddev_769 = 8.763872947670246e-06 # 130.1 bit security
stddev_873 = 1.3962609252411138e-06 # 130.1 bit security
stddev_953 = 3.4906523131027844e-07 # 130.2 bit security
stddev_2048 = 9.25119974676756e-16 # 130.7 bit security
stddev_4096 = 2.168404344971009e-19 # 218.5 bit security

cmux1 = (
    "CMux1",
    (2^23, 1), # (B_pbs, l_pbs)
    (2^8, 5, 2^64), # (B_tr, l_tr, b_tr)
    (2^25, 1), # (B_ss, l_ss)
    (2^3, 4), # (B_cbs, l_cbs)
)

cmux2 = (
    "CMux2",
    (2^15, 2), # (B_pbs, l_pbs)
    (2^7, 6, 2^64), # (B_tr, l_tr, b_tr)
    (2^17, 2), # (B_ss, l_ss)
    (2^4, 4), # (B_cbs, l_cbs)
)

cmux3 = (
    "CMux3",
    (2^15, 2), # (B_pbs, l_pbs)
    (2^7, 6, 2^35), # (B_tr, l_tr, b_tr)
    (2^17, 2), # (B_ss, l_ss)
    (2^4, 4), # (B_cbs, l_cbs)
)

wopbs_2_2 = (
    "wopbs_param_message_2_carry_2_ks_pbs",
    (769, stddev_769^2), # (LWE dim, LWE var), 130.1 bit security
    (2^15, 2), # (PBS base, PBS level)
    (2^5, 3), # (CBS base, CBS level) (note: (2^6, 3) is better)
    (2^6, 2), # (KS base, KS level)
    0, # theta
    4, # log_modulus
    1, # num_extract
)

wopbs_3_3 = (
    "wopbs_param_message_3_carry_3_ks_pbs",
    (873, stddev_873^2), # (LWE dim, LWE var), 130.1 bit security
    (2^9, 4), # (PBS base, PBS level)
    (2^6, 3), # (CBS base, CBS level)
    (2^10, 1), # (KS base, KS level)
    0, # theta
    6, # log_modulus
    1, # num_extract
)

wopbs_4_4 = (
    "wopbs_param_message_4_carry_4_ks_pbs",
    (953, stddev_953^2), # (LWE dim, LWE var), 130.2 bit security
    (2^9, 4), # (PBS base, PBS level)
    (2^4, 6), # (CBS base, CBS level)
    (2^11, 1), # (KS base, KS level)
    0, # theta
    8, # log_modulus
    1, # num_extract
)

improved_wopbs_2_2 = (
    "improved wopbs_2_2",
    (769, stddev_769^2), # (LWE dim, LWE var), 130.1 bit security
    (2^15, 2), # (PBS base, PBS level)
    (2^7, 7, 2^35), # (Tr base, Tr level, split base)
    (2^17, 2), # (SS base, SS level)
    (2^4, 4), # (CBS base, CBS level) with increased level
    (2^4, 3), # (KS base, KS level) with increased level
    2, # theta
    4, # log_modulus
    2, # num_extract
)

improved_wopbs_3_3 = (
    "improved wopbs_3_3",
    (873, stddev_873^2), # (LWE dim, LWE var), 130.1 bit security
    (2^11, 3), # (PBS base, PBS level)
    (2^12, 4, 2^40), # (Tr base, Tr level, split fft)
    (2^10, 4), # (SS base, SS level),
    (2^15, 3, 2^42), # (KS_to_large base, KS_to_large level, split fft),
    (2^12, 3, 2^40), # (KS_from_large base, KS_from_large level, split fft),
    (2^5, 4), # (CBS base, CBS level) with increased level
    (2^7, 2), # (KS base, KS level) with increased level
    2, # theta
    6, # log_modulus
    3, # num_extract
)

improved_wopbs_4_4 = (
    "improved wopbs_4_4",
    (953, stddev_953^2), # (LWE dim, LWE var), 130.2 bit security
    (2^9, 4), # (PBS base, PBS level)
    (2^9, 6, 2^37), # (Tr base, Tr level, split fft)
    (2^10, 4), # (SS base, SS level),
    (2^15, 3, 2^42), # (KS_to_large base, KS_to_large level, split fft),
    (2^10, 4, 2^38), # (KS_from_large base, KS_from_large level, split fft),
    (2^3, 8), # (CBS base, CBS level) with increased level
    (2^7, 2), # (KS base, KS level) with increased level
    3, # theta
    8, # log_modulus
    2, # num_extract
)