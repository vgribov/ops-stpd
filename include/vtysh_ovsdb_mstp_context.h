/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/******************************************************************************
 *    File               : vtysh_ovsdb_mstp_context.h
 *    Description        : MSTP Protocol show running config API
 ******************************************************************************/
#ifndef VTYSH_OVSDB_MSTP_CONTEXT_H
#define VTYSH_OVSDB_MSTP_CONTEXT_H

vtysh_ret_val vtysh_config_context_mstp_clientcallback(void *p_private);
vtysh_ret_val vtysh_mstp_context_clientcallback(void *p_private);
vtysh_ret_val vtysh_intf_context_mstp_clientcallback(void *p_private);

#endif /* VTYSH_OVSDB_MSTP_CONTEXT_H */
