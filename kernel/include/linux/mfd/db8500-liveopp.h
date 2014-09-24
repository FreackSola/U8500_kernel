/*
 * DB8500 Live OPP(Performance Operating Points)
 * 
 * Author: Huang Ji (cocafe@xda-developers.com) <cocafehj@gmail.com>
 * 
 * This program is free software and is provided to you under 
 * the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, 
 * and any use by you of this program is subject to the terms of such GNU licence.
 * 
 * A copy of the licence is included with the program, 
 * and can also be obtained from Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#define PRCMU_ARMFIX_REG		0x000
#define PRCMU_ARMPLL_REG		0x088

/*
 * Varm has three voltage selections
 * But Selection 3 is never used
 */
#define AB8500_VARM_SEL1 		0x0B
#define AB8500_VARM_SEL2 		0x0C
#define AB8500_VARM_SEL3 		0x0D
#define AB8500_VBB_REG 			0x11

#define ARM_IGNORE 0x10

/**
 * struct liveopp_arm_table - Custom frequency and voltage table
 * @freq_show:		Frequency(KHz) showed in userspace, no effect on real clock
 * @freq_raw:		Manually calculated frequency(KHz) for showing, no effect on real clock
 * @arm_opp:		STE ARM OPP index to use, we need to setup ARM OPP first
 * @arm_opp_rec(overy):	Workaround to fix dead issue when scales down from overclocked freqs
 * @extarm_raw:		Raw register value of ARMCLKFIX_MGT in PRCMU
 * @pllarm_raw:		Raw register value of PLLARM_FREQ in PRCMU
 * @varm_sel:		Varm voltage selection (1/2/3)
 * @varm_raw:		Raw register value of Varm regulator in AB850x
 * @vbbx_raw:		Raw register value of Vbbp and Vbbn regulator in AB850x
 * @set_pllarm:		Whether override the default PRCMU OPP frequency
 * @set_volt:		Whether override the default PRCMU OPP voltage
 */
struct liveopp_arm_table
{
	u32 	freq_show;
	u32 	freq_raw;
	u8  	arm_opp;
	u32 	extarm_raw;
	u32 	pllarm_raw;
	u8 	varm_sel;
	u8 	varm_raw;
	u8  	vbb_raw;
};
u8 varm_raw=0x3F;
u8 vbb_raw=0x8F;
u8 varm_raw_rec=0x24;
u8 vbb_raw_rec=0xDB;
/* PLLARM in 38400KHz steps */
#define PLLARM_FREQ_STEPS		38400
#define PLLARM_MAXOPP			0x0001011A
#define PLLARM_FREQ100OPP		0x00050168
#define AB8500_VAPE_SEL1 		0x0E
#define PRCMU_SGACLK			0x0014
#define PRCMU_PLLSOC0			0x0080
