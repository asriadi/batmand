/*
 * Copyright (C) 2009-2010 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <lindner_marek@yahoo.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */


#define SYS_MODULE_PATH "/sys/module/batman_adv/"
#define SYS_BATIF_PATH "/sys/class/net/bat0/mesh/"
#define SYS_LOG_LEVEL "parameters/debug"
#define SYS_LOG "log"
#define SYS_ORIGINATORS "originators"
#define SYS_TRANSTABLE_LOCAL "transtable_local"
#define SYS_TRANSTABLE_GLOBAL "transtable_global"
#define SYS_AGGR "aggregate_ogm"
#define SYS_BONDING "bonding"

void originators_usage(void);
void trans_local_usage(void);
void trans_global_usage(void);
void aggregation_usage(void);
void bonding_usage(void);
int log_print(int argc, char **argv);
int handle_loglevel(int argc, char **argv);
int handle_sys_table(int argc, char **argv, char *file_path, void table_usage(void));
int handle_sys_setting(int argc, char **argv, char *file_path, void setting_usage(void));
