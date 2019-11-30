from construct import *

##########################################
########     SignIn Server        ########
##########################################
SignInRequest = Struct(
    "req_type" / CString("utf8"),
    "id" / CString("utf8"),
    "skey" / CString("utf8"),
    "unk" / CString("utf8"),
)

SignInResp = EmbeddedSwitch(
    Struct(
        "resp_code" / Byte,
    ),
    this.resp_code,
    {
        1: Struct(
            #"unk_0" / If(False, PaddedString(16, "utf8")), # Unknown condition.
            "unk_hostname_count" / Byte,
            "entrance_server_count" / Byte,
            "character_count" / Byte,
            "login_token_number" / Int32ub,
            "login_token" / PaddedString(16, "utf8"),
            # "unk_3B74" / If(False, PascalString(Byte, "utf8")), # Unknown condition.
            "unk_3AE8" / Int32ub,
            "unk_hostnames" / Array(this.unk_hostname_count, PascalString(Byte, "utf8")),
            "entrance_servers" / Array(this.entrance_server_count, PascalString(Byte, "utf8")),
            "characters" / Array(this.character_count,
                Struct(
                    "character_id" / Int32ub,
                    "unk_1" / Int16ub,
                    "unk_2" / Int16ub,
                    "unk_3" / Int32ub,
                    "unk_4" / Byte,
                    "unk_5" / Byte,
                    "unk_6" / Byte,
                    "unk_7" / Byte,
                    "unk_8" / PaddedString(16, "utf8"),
                    "unk_9" / PaddedString(32, "utf8"),
                    "unk_10" / If(this.unk_7 > 0, Struct(
                        "unk_0" / Int16ub,
                        "unk_1" / Byte,
                        "unk_2" / Byte,
                        )
                    ),
                )
            ),
            "friends_list_count" / Byte,
            "unk_count_extended_0" / If(this.friends_list_count == 255, Int16ub),
            "friends_list" / Array(this.friends_list_count if this.friends_list_count < 255 else this.unk_count_extended_0,
                Struct(
                    "unk_0" / Int32ub,
                    "unk_1" / Int32ub,
                    "player_name" / PascalString(Byte, "ansi")
                )
            ),
            "guild_members_count" / Byte,
            "guild_members_count_extended" / If(this.guild_members_count == 255, Int16ub),
            "guild_members" / Array(this.guild_members_count if this.guild_members_count < 255 else this.guild_members_count_extended,
                Struct(
                    "unk_0" / Int32ub,
                    "unk_1" / Int32ub,
                    "player_name" / PascalString(Byte, "ansi")
                )
            ),
            "notice_count" / Byte,
            "notices" / Array(this.notice_count,
                Struct(
                    "unk_0" / Byte,
                    "unk_1" / Byte,
                    "notice_html" / PascalString(Int16ub, "ansi")
                )
            ),
            "some_last_played_character_id" / Int32ub,
            "unk_flags" / Int32ub,
            "unk_data_blob" / PascalString(Int16ub, "ansi"),

            "unk_key_str_type" / Int16ub,
            "unk_key_str_id" / If(this.unk_key_str_type == 0xCA10, Int16ub),
            "unk_key_str_0" / If(this.unk_key_str_id == 20000, PascalString(Int16ub, "utf8")),
            "unk_key_str_1" / If(this.unk_key_str_id == 20002 and this.unk_flags & 0x1000000, PascalString(Int16ub, "utf8")),

            "unk_25E4_count" / Byte,
            "unk_25E4" / Array(this.unk_25E4_count,
                Struct(
                    "unk_0" / Byte,
                    "unk_1" / Int32ub,
                    "unk_2" / PascalString(Byte, "ansi")
                )
            ),
            # Stop if EOF.


            "unk_str_type" / Int16ub,
            "unk_str_id_0" / If(this.unk_str_type == 0xCA11, Int16ub),
            "unk_str_id_1" / If(this.unk_str_id_0 == 1, Int16ub),
            "unk_server_ip" / If(this.unk_str_id_1 == 20000, PascalString(Int16ub, "utf8")),
            # Stop if EOF.

            "unk_488" / Int32ub,
            "unk_490" / Int32ub,
            # Stop if EOF.


            "unk_3668" / Int32ub,
            "unk_3670" / Int32ub,
            "unk_3678" / Int32ub,
            "unk_3680_count" / Byte,
            "unk_3680" / Array(this.unk_3680_count,
                Struct(
                    "unk_0" / Int32ub,
                )
            ),

            "unk_3688_count" / Byte,
            "unk_3688" / Array(this.unk_3688_count,
                Struct(
                    "unk_0" / Byte,
                )
            ),

            # Maybe still more?
            ),
        0x17: Struct(), # Region blocked.
    }
)

ServerInfo = Struct(
    "host_ip_4byte" / Int32ub,
    "unk_1" / Int16ub, # Server ID maybe?
    "unk_2" / Int16ub,
    "channel_count" / Int16ub,
    "unk_4" / Byte,
    "unk_5" / Byte,
    "unk_6" / Byte,
    "name" / Bytes(66), # Shift-JIS.
    "unk_trailer" / Int32ub, # THIS ONLY EXISTS IF Binary8Header.type == "SV2", NOT "SVR"!
)

ChannelInfo = Struct(
    "port" / Int16ub,
    "unk_1" / Int16ub, # Channel ID maybe?
    "max_players" / Int16ub,
    "current_players" / Int16ub,
    "unk_4" / Int16ub,
    "unk_5" / Int16ub,
    "unk_6" / Int16ub,
    "unk_7" / Int16ub,
    "unk_8" / Int16ub,
    "unk_9" / Int16ub,
    "unk_10" / Int16ub,
    "unk_11" / Int16ub,
    "unk_12" / Int16ub,
    "unk_13" / Int16ub,
)

##########################################
########     SignIn Server END    ########
##########################################

##########################################
########     Entrance server      ########
##########################################
Binary8Header = Struct(
    "server_type" / Bytes(3),
    "entry_count" / Int16ub,
    "body_size" / Int16ub,
    "checksum" / Int32ub,
)
##########################################
########     Entrance server END  ########
##########################################

MsgHeader = Struct(
    "opcode" / Int16ub,
    "ack_handle" / Int32ub,
) 

MsgSysPing = Struct(
    "opcode" / Int16ub,
    "ack_handle" / Int32ub,
)

MsgSysAck = Struct(
    "opcode" / Int16ub,
    "ack_handle" / Int32ub,
    "unk" / Int16ub,
    "response_size" / Int16ub,
    "response_data" / Bytes(this.response_size),
)

MsgSysLoginRequest = Struct(
    "opcode" / Int16ub,
    "ack_handle" / Int32ub,
    "unk_0" / Int32ub,
    "unk_1" / Int32ub,
    "hardcoded_0" / Default(Int16ub, 0), # Hardcoded 0x00 0x00
    "hardcoded_1" / Default(Int16ub, 0xB), # Hardcoded 0x00 0x0B
    "unk_2" / Int32ub, # Same value as unk_0
    "hardcoded_2" / Default(Int16ub, 0x0), # Hardcoded 0x00 0x00
    "hardcoded_3" / Default(Int16ub, 0x11), # Hardcoded 0x00 0x11 -- login token length.
    "login_token" / PaddedString(17, "utf8"),
)

MsgSysGetFile = Struct(
    "opcode" / Int16ub, # MSG_SYS_GET_FILE
    "ack_handle" / Int32ub,
    "is_scenario_file" / Byte,
    "filename_len" / Byte,
    "filename" / Bytes(this.filename_len-1),
    "scenario_identifer" / Default(If(this.is_scenario_file == 1, Struct(
        "unk_0" / Byte,
        "unk_1" / Int32ub,
        "unk_2" / Byte,
        "unk_3" / Byte,
    )), None),
)

