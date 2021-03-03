
type file_id: record {
        vlan: int &log &optional;
        vlan_inner: int &log &optional;
};

redef record Files::Info += {
	id:    file_id   &log  &optional;
};


event file_sniff(f: fa_file, meta: fa_metadata)
	{
	for ( cid, c in f$conns )
		{
		if ( c?$vlan )
			{
			f$info$id = [$vlan = c$vlan];
			if ( c?$inner_vlan )
				f$info$id$vlan_inner = c$inner_vlan;
			}
		break;

		}
	}

