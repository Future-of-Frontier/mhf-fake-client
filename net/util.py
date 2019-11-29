def ip_string_from_uint32(host_u32):
	b0 = (host_u32 >> 0) & 0xFF
	b1 = (host_u32 >> 8) & 0xFF
	b2 = (host_u32 >> 16) & 0xFF
	b3 = (host_u32 >> 24) & 0xFF

	return "{}.{}.{}.{}".format(b0, b1, b2, b3)