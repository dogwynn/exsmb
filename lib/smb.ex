defmodule Smb do
  @moduledoc """
  Documentation for `Smb`.
  """
  import Constants

  # SMB Packet
  const :smb2_packet_size, 64

  # SMB Commands
  const :smb2_negotiate, 0x0000 #
  const :smb2_session_setup, 0x0001 #
  const :smb2_logoff, 0x0002 #
  const :smb2_tree_connect, 0x0003 #
  const :smb2_tree_disconnect, 0x0004 #
  const :smb2_create, 0x0005 #
  const :smb2_close, 0x0006 #
  const :smb2_flush, 0x0007 #
  const :smb2_read, 0x0008 #
  const :smb2_write, 0x0009 #
  const :smb2_lock, 0x000A #
  const :smb2_ioctl, 0x000B #
  const :smb2_cancel, 0x000C #
  const :smb2_echo, 0x000D #
  const :smb2_query_directory, 0x000E #
  const :smb2_change_notify, 0x000F
  const :smb2_query_info, 0x0010 #
  const :smb2_set_info, 0x0011
  const :smb2_oplock_break, 0x0012

  # SMB Flags
  const :smb2_flags_server_to_redir, 0x00000001
  const :smb2_flags_async_command, 0x00000002
  const :smb2_flags_related_operations, 0x00000004
  const :smb2_flags_signed, 0x00000008
  const :smb2_flags_dfs_operations, 0x10000000
  const :smb2_flags_replay_operation, 0x80000000

  # SMB Error SymLink Flags
  const :symlink_flag_absolute, 0x0
  const :symlink_flag_relative, 0x1

  # SMB2_NEGOTIATE
  # Security Modes
  const :smb2_negotiate_signing_enabled, 0x1
  const :smb2_negotiate_signing_required, 0x2

  # SMB2_NEGOTIATE_CONTEXT
  const :smb2_preauth_integrity_capabilities, 0x1
  const :smb2_encryption_capabilities, 0x2
  const :smb2_compression_capabilities, 0x3
  const :smb2_netname_negotiate_context_id, 0x5

  # SMB2_COMPRESSION_CAPABILITIES
  const :smb2_compression_capabilities_flag_none, 0x0
  const :smb2_compression_capabilities_flag_chained, 0x1

  # Compression Algorithms
  const :compression_algorithm_none, 0x0
  const :compression_algorithm_lznt1, 0x1
  const :compression_algorithm_lz77, 0x2
  const :compression_algorithm_lz77_huffman, 0x3
  const :compression_algorithm_pattern_v1, 0x4

  # Capabilities
  const :smb2_global_cap_dfs, 0x01
  const :smb2_global_cap_leasing, 0x02
  const :smb2_global_cap_large_mtu, 0x04
  const :smb2_global_cap_multi_channel, 0x08
  const :smb2_global_cap_persistent_handles, 0x10
  const :smb2_global_cap_directory_leasing, 0x20
  const :smb2_global_cap_encryption, 0x40

  # Dialects
  const :smb2_dialect_002, 0x0202
  const :smb2_dialect_21, 0x0210
  const :smb2_dialect_30, 0x0300
  const :smb2_dialect_302, 0x0302  #SMB 3.0.2
  const :smb2_dialect_311, 0x0311  #SMB 3.1.1
  const :smb2_dialect_wildcard, 0x02FF

  # SMB2_SESSION_SETUP
  # Flags
  const :smb2_session_flag_binding, 0x01
  const :smb2_session_flag_is_guest, 0x01
  const :smb2_session_flag_is_null, 0x02
  const :smb2_session_flag_encrypt_data, 0x04

  # SMB2_TREE_CONNECT
  # Types
  const :smb2_share_type_disk, 0x1
  const :smb2_share_type_pipe, 0x2
  const :smb2_share_type_print, 0x3

  # Share Flags
  const :smb2_shareflag_manual_caching, 0x00000000
  const :smb2_shareflag_auto_caching, 0x00000010
  const :smb2_shareflag_vdo_caching, 0x00000020
  const :smb2_shareflag_no_caching, 0x00000030
  const :smb2_shareflag_dfs, 0x00000001
  const :smb2_shareflag_dfs_root, 0x00000002
  const :smb2_shareflag_restrict_exclusive_opens, 0x00000100
  const :smb2_shareflag_force_shared_delete, 0x00000200
  const :smb2_shareflag_allow_namespace_caching, 0x00000400
  const :smb2_shareflag_access_based_directory_enum, 0x00000800
  const :smb2_shareflag_force_levelii_oplock, 0x00001000
  const :smb2_shareflag_enable_hash_v1, 0x00002000
  const :smb2_shareflag_enable_hash_v2, 0x00004000
  const :smb2_shareflag_encrypt_data, 0x00008000

  # Capabilities
  const :smb2_share_cap_dfs, 0x00000008
  const :smb2_share_cap_continuous_availability, 0x00000010
  const :smb2_share_cap_scaleout, 0x00000020
  const :smb2_share_cap_cluster, 0x00000040

  # SMB_CREATE
  # Oplocks
  const :smb2_oplock_level_none, 0x00
  const :smb2_oplock_level_ii, 0x01
  const :smb2_oplock_level_exclusive, 0x08
  const :smb2_oplock_level_batch, 0x09
  const :smb2_oplock_level_lease, 0xFF

  # Impersonation Level
  const :smb2_il_anonymous, 0x00000000
  const :smb2_il_identification, 0x00000001
  const :smb2_il_impersonation, 0x00000002
  const :smb2_il_delegate, 0x00000003

  # File Attributes
  const :file_attribute_archive, 0x00000020
  const :file_attribute_compressed, 0x00000800
  const :file_attribute_directory, 0x00000010
  const :file_attribute_encrypted, 0x00004000
  const :file_attribute_hidden, 0x00000002
  const :file_attribute_normal, 0x00000080
  const :file_attribute_not_content_indexed, 0x00002000
  const :file_attribute_offline, 0x00001000
  const :file_attribute_readonly, 0x00000001
  const :file_attribute_reparse_point, 0x00000400
  const :file_attribute_sparse_file, 0x00000200
  const :file_attribute_system, 0x00000004
  const :file_attribute_temporary, 0x00000100
  const :file_attribute_integrity_stream, 0x00000800
  const :file_attribute_no_scrub_data, 0x00020000

  # Share Access
  const :file_share_read, 0x00000001
  const :file_share_write, 0x00000002
  const :file_share_delete, 0x00000004

  # Create Disposition
  const :file_supersede, 0x00000000
  const :file_open, 0x00000001
  const :file_create, 0x00000002
  const :file_open_if, 0x00000003
  const :file_overwrite, 0x00000004
  const :file_overwrite_if, 0x00000005

  # Create Options
  const :file_directory_file, 0x00000001
  const :file_write_through, 0x00000002
  const :file_sequential_only, 0x00000004
  const :file_no_intermediate_buffering, 0x00000008
  const :file_synchronous_io_alert, 0x00000010
  const :file_synchronous_io_nonalert, 0x00000020
  const :file_non_directory_file, 0x00000040
  const :file_complete_if_oplocked, 0x00000100
  const :file_no_ea_knowledge, 0x00000200
  const :file_random_access, 0x00000800
  const :file_delete_on_close, 0x00001000
  const :file_open_by_file_id, 0x00002000
  const :file_open_for_backup_intent, 0x00004000
  const :file_no_compression, 0x00008000
  const :file_reserve_opfilter, 0x00100000
  const :file_open_reparse_point, 0x00200000
  const :file_open_no_recall, 0x00400000
  const :file_open_for_free_space_query, 0x00800000

  # File Access Mask / Desired Access
  const :file_read_data, 0x00000001
  const :file_write_data, 0x00000002
  const :file_append_data, 0x00000004
  const :file_read_ea, 0x00000008
  const :file_write_ea, 0x00000010
  const :file_execute, 0x00000020
  const :file_read_attributes, 0x00000080
  const :file_write_attributes, 0x00000100
  const :delete, 0x00010000
  const :read_control, 0x00020000
  const :write_dac, 0x00040000
  const :write_owner, 0x00080000
  const :synchronize, 0x00100000
  const :access_system_security, 0x01000000
  const :maximum_allowed, 0x02000000
  const :generic_all, 0x10000000
  const :generic_execute, 0x20000000
  const :generic_write, 0x40000000
  const :generic_read, 0x80000000

  # Directory Access Mask
  const :file_list_directory, 0x00000001
  const :file_add_file, 0x00000002
  const :file_add_subdirectory, 0x00000004
  const :file_traverse, 0x00000020
  const :file_delete_child, 0x00000040

  # Create Contexts
  const :smb2_create_ea_buffer, 0x45787441
  const :smb2_create_sd_buffer, 0x53656344
  const :smb2_create_durable_handle_request, 0x44486e51
  const :smb2_create_durable_handle_reconnect, 0x44486e43
  const :smb2_create_allocation_size, 0x416c5369
  const :smb2_create_query_maximal_access_request, 0x4d784163
  const :smb2_create_timewarp_token, 0x54577270
  const :smb2_create_query_on_disk_id, 0x51466964
  const :smb2_create_request, 0x52714c73
  const :smb2_create_request_lease_v2, 0x52714c73
  const :smb2_create_durable_handle_request_v2, 0x44483251
  const :smb2_create_durable_handle_reconnect_v2, 0x44483243
  const :smb2_create_app_instance_id, 0x45BCA66AEFA7F74A9008FA462E144D74

  # Flags
  const :smb2_create_flag_reparsepoint, 0x1
  const :file_need_ea, 0x80

  # CreateAction
  const :file_superseded, 0x00000000
  const :file_opened, 0x00000001
  const :file_created, 0x00000002
  const :file_overwritten, 0x00000003

  # SMB2_CREATE_REQUEST_LEASE states
  const :smb2_lease_none, 0x00
  const :smb2_lease_read_caching, 0x01
  const :smb2_lease_handle_caching, 0x02
  const :smb2_lease_write_caching, 0x04

  # SMB2_CREATE_REQUEST_LEASE_V2 Flags
  const :smb2_lease_flag_parent_lease_key_set, 0x4

  # SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 Flags
  const :smb2_dhandle_flag_persistent, 0x02

  # SMB2_CLOSE
  # Flags
  const :smb2_close_flag_postquery_attrib, 0x0001

  # SMB2_READ
  # Channel
  const :smb2_channel_none, 0x00
  const :smb2_channel_rdma_v1, 0x01

  # SMB2_WRITE
  # Flags
  const :smb2_writeflag_write_through, 0x01

  # Lease Break Notification
  const :smb2_notify_break_lease_flag_ack_required, 0x01

  # SMB_LOCK
  # Flags
  const :smb2_lockflag_shared_lock, 0x01
  const :smb2_lockflag_exclusive_lock, 0x02
  const :smb2_lockflag_unlock, 0x04
  const :smb2_lockflag_fail_immediately, 0x10

  # SMB IOCTL
  # Control Codes
  const :fsctl_dfs_get_referrals, 0x00060194
  const :fsctl_pipe_peek, 0x0011400C
  const :fsctl_pipe_wait, 0x00110018
  const :fsctl_pipe_transceive, 0x0011C017
  const :fsctl_srv_copychunk, 0x001440F2
  const :fsctl_srv_enumerate_snapshots, 0x00144064
  const :fsctl_srv_request_resume_key, 0x00140078
  const :fsctl_srv_read_hash, 0x001441bb
  const :fsctl_srv_copychunk_write, 0x001480F2
  const :fsctl_lmr_request_resiliency, 0x001401D4
  const :fsctl_query_network_interface_info, 0x001401FC
  const :fsctl_set_reparse_point, 0x000900A4
  const :fsctl_delete_reparse_point, 0x000900AC
  const :fsctl_dfs_get_referrals_ex, 0x000601B0
  const :fsctl_file_level_trim, 0x00098208
  const :fsctl_validate_negotiate_info, 0x00140204

  # Flags
  const :smb2_0_ioctl_is_fsctl, 0x1

  # SRV_READ_HASH
  # Type
  const :srv_hash_type_peer_dist, 0x01

  # Version
  const :srv_hash_ver_1, 0x1
  const :srv_hash_ver_2, 0x2

  # Retrieval Type
  const :srv_hash_retrieve_hash_based, 0x01
  const :srv_hash_retrieve_file_based, 0x02

  # NETWORK_INTERFACE_INFO
  # Capabilities
  const :rss_capable, 0x01
  const :rdma_capable, 0x02

  # SMB2_QUERY_DIRECTORIES
  # Information Class
  const :file_directory_information, 0x01
  const :file_full_directory_information, 0x02
  const :fileid_full_directory_information, 0x26
  const :file_both_directory_information, 0x03
  const :fileid_both_directory_information, 0x25
  const :filenames_information, 0x0C

  # Flags
  const :smb2_restart_scans, 0x01
  const :smb2_return_single_entry, 0x02
  const :smb2_index_specified, 0x04
  const :smb2_reopen, 0x10

  # SMB2_CHANGE_NOTIFY
  # Flags
  const :smb2_watch_tree, 0x01

  # Filters
  const :file_notify_change_file_name, 0x00000001
  const :file_notify_change_dir_name, 0x00000002
  const :file_notify_change_attributes, 0x00000004
  const :file_notify_change_size, 0x00000008
  const :file_notify_change_last_write, 0x00000010
  const :file_notify_change_last_access, 0x00000020
  const :file_notify_change_creation, 0x00000040
  const :file_notify_change_ea, 0x00000080
  const :file_notify_change_security, 0x00000100
  const :file_notify_change_stream_name, 0x00000200
  const :file_notify_change_stream_size, 0x00000400
  const :file_notify_change_stream_write, 0x00000800

  # FILE_NOTIFY_INFORMATION
  # Actions
  const :file_action_added, 0x00000001
  const :file_action_removed, 0x00000002
  const :file_action_modified, 0x00000003
  const :file_action_renamed_old_name, 0x00000004
  const :file_action_renamed_new_name, 0x00000005

  # SMB2_QUERY_INFO
  # InfoTypes
  const :smb2_0_info_file, 0x01
  const :smb2_0_info_filesystem, 0x02
  const :smb2_0_info_security, 0x03
  const :smb2_0_info_quota, 0x04

  # File Information Classes
  const :smb2_sec_info_00, 0
  const :smb2_file_access_info, 8
  const :smb2_file_alignment_info, 17
  const :smb2_file_all_info, 18
  const :smb2_file_allocation_info, 19
  const :smb2_file_alternate_name_info, 21
  const :smb2_attribute_tag_info, 35
  const :smb2_file_basic_info, 4
  const :smb2_file_both_directory_info, 3
  const :smb2_file_compression_info, 28
  const :smb2_file_directory_info, 1
  const :smb2_file_disposition_info, 13
  const :smb2_file_ea_info, 7
  const :smb2_file_end_of_file_info, 20
  const :smb2_full_directory_info, 2
  const :smb2_full_ea_info, 15
  const :smb2_file_hardlink_info, 46
  const :smb2_file_id_both_directory_info, 37
  const :smb2_file_id_full_directory_info, 38
  const :smb2_file_id_global_tx_directory_info, 50
  const :smb2_file_internal_info, 6
  const :smb2_file_link_info, 11
  const :smb2_file_mailslot_query_info, 26
  const :smb2_file_mailslot_set_info, 27
  const :smb2_file_mode_info, 16
  const :smb2_file_move_cluster_info, 31
  const :smb2_file_name_info, 9
  const :smb2_file_names_info, 12
  const :smb2_file_network_open_info, 34
  const :smb2_file_normalized_name_info, 48
  const :smb2_file_object_id_info, 29
  const :smb2_file_pipe_info, 23
  const :smb2_file_pipe_local_info, 24
  const :smb2_file_pipe_remote_info, 25
  const :smb2_file_position_info, 14
  const :smb2_file_quota_info, 32
  const :smb2_file_rename_info, 10
  const :smb2_file_reparse_point_info, 33
  const :smb2_file_sfio_reserve_info, 44
  const :smb2_file_short_name_info, 45
  const :smb2_file_standard_info, 5
  const :smb2_file_standard_link_info, 54
  const :smb2_file_stream_info, 22
  const :smb2_file_tracking_info, 36
  const :smb2_file_valid_data_length_info, 39

  # File System Information Classes
  const :smb2_filesystem_volume_info, 1
  const :smb2_filesystem_label_info, 2
  const :smb2_filesystem_size_info, 3
  const :smb2_filesystem_device_info, 4
  const :smb2_filesystem_attribute_info, 5
  const :smb2_filesystem_control_info, 6
  const :smb2_filesystem_full_size_info, 7
  const :smb2_filesystem_object_id_info, 8
  const :smb2_filesystem_driver_path_info, 9
  const :smb2_filesystem_sector_size_info, 11

  # Additional information
  const :owner_security_information, 0x00000001
  const :group_security_information, 0x00000002
  const :dacl_security_information, 0x00000004
  const :sacl_security_information, 0x00000008
  const :label_security_information, 0x00000010

  # Flags
  const :sl_restart_scan, 0x00000001
  const :sl_return_single_entry, 0x00000002
  const :sl_index_specified, 0x00000004

  # TRANSFORM_HEADER
  const :smb2_encryption_aes128_ccm, 0x0001
  const :smb2_encryption_aes128_gcm, 0x0002



  @doc """
  Hello world.

  ## Examples

      iex> Smb.hello()
      :world

  """
  def hello do
    :world
  end
end
