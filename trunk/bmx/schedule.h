/*
 * Copyright (C) 2010 BMX contributors:
 * Axel Neumann
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
 */




void init_schedule( void );
void change_selects( void );
void cleanup_schedule( void );
void register_task( uint32_t timeout, void (* task) (void *), void *data );
IDM_T remove_task(void (* task) (void *), void *data);
uint32_t whats_next( void );
void wait4Event( uint32_t timeout );

