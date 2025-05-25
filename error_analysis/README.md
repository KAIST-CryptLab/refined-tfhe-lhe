# Error Analysis
This is a [sage](https://www.sagemath.org/) implementation of the error analysis.

## Contents
- Analysis for the parameters used in the paper:
  - FFT-based bitwise CBS: [fft_based_bit_cbs.sage](fft_based_bit_cbs.sage)
  - Bitwise CBS for other works: [bit_cbs_others.sage](bit_cbs_others.sage)
  - Integer input LHE: [integer_input_lhe.sage](integer_input_lhe.sage)
  - AES evaluation: [aes_eval.sage](aes_eval.sage)
- Tool for finding optimized parameters for FFT-based bitwise CBS:
  - [finding_param.sage](finding_param.sage)

## How to Use
Run `sage FILENAME.sage`. For the analyses of the parameters used in the paper, the result according to the hard-coded parameters would be printed.

For finding parameters for FFT-based bitwise CBS, it takes inputs for the gadget lengths (and gadget bases).
- `-l l_ks l_pbs l_tr l_ss l_cbs`: specifying gadget lengths results in optimal gadget bases.
- `-ns`: flag to denote not using split FFT.
- The default parameters also can be changed. Use `-h` to see the details.
 
 