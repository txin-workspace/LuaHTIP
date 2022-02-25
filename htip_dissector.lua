require "bit32"

do

	local p_htip = Proto("HTIP", "Home-network Topology Identifying Protocol");

	local head_dest = ProtoField.new("Destnation", "p_htip.head_dest", ftypes.ETHER)
	local head_sour = ProtoField.new("Source", "p_htip.head_sour" , ftypes.ETHER)
	local head_type = ProtoField.new("EtherType", "p_htip.head_type", ftypes.BYTES)
	local mac_addr = ProtoField.new("Mac Address", "p_htip.mac_addr", ftypes.ETHER)
	-- local tlv_type = ProtoField.new("type", "p_htip.tlv_type", ftypes.INT8)
	-- local tlv_length = ProtoField.new("length", "p_htip.tlv_type", ftypes.INT16)

	p_htip.fields = {head_dest, head_sour, head_type, mac_addr}

	--justData
	function setUintData(buffer, treeNode, offset, dataName, dataLen)
		treeNode:add(buffer(offset, dataLen), dataName..": "..buffer(offset, dataLen):uint())
	end
	function setStringData(buffer, treeNode, offset, dataName, dataLen)
		treeNode:add(buffer(offset, dataLen), dataName..": "..buffer(offset, dataLen):string())
	end
	function setUnkonwData(buffer, treeNode, offset, dataName, dataLen)
		treeNode:add(buffer(offset, dataLen), dataName..": "..buffer(offset, dataLen))
	end

	--lenAndData
	function setLenAndData(buffer, treeNode, offset, dataName, dataType)
		local dataLen = buffer(offset, 1):uint()
		treeNode:add(buffer(offset, 1), dataName.." data length: " ..dataLen)
		offset = offset + 1
		if(dataType == "string") then setStringData(buffer, treeNode, offset, dataName, dataLen)
		elseif(dataType == "uint") then setUintData(buffer, treeNode, offset, dataName, dataLen)
		else setUnkonwData(buffer, treeNode, offset, dataName, dataLen)
		end
		
		offset = offset + dataLen
		return offset
	end

	--tlvNameを書く
	function ttcSubtypeNameWrite(tlvType)
		if(tlvType == 1)     then return "Equipment Information"
		elseif(tlvType == 2) then return "Connection Configuration Information"
		elseif(tlvType == 3) then return "MAC Address List"
		elseif(tlvType == 4) then return "Extended Connection Configuration Information"
		elseif(tlvType == 5) then return "Extended MAC Address List"
		elseif(tlvType == 6) then return "Setting Information"
		else return "Unknown TLV"
		end
	end

	--return data
	function writeData(buffer, offset, vtype)
		local dataLen = buffer(offset, 1):uint()
		if (vtype == "string") then
			if (buffer(offset +dataLen, 1):string() == "\0") then return buffer(offset + 1, dataLen -1)
			else return buffer(offset + 1, dataLen)
			end	
		else return buffer(offset + 1, dataLen)
		end
	end
	--ttcSubtypeを書く
	function eiIDNameWrite(eiID, buffer, offset)
		if(eiID == 1)       then return "indicator : "..writeData(buffer, offset, "string"):string()
		elseif(eiID == 2)   then return "maker code : "..writeData(buffer, offset, "string"):string()
		elseif(eiID == 3)   then return "model name : "..writeData(buffer, offset, "string"):string()
		elseif(eiID == 4)   then return "model number : "..writeData(buffer, offset, "string"):string()
		elseif(eiID == 20)  then return "channel usage status : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 21)  then return "radio wave intensity information : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 22)  then return "communication error rate : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 23)  then return "response time : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 24)  then return "number of related devices : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 25)  then return "number of active nodes : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 26)  then return "radio quality : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 27)  then return "number of retransmissions : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 50)  then return "status information : "..writeData(buffer, offset, "string"):string()
		elseif(eiID == 51)  then return "CPU usage : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 52)  then return "memory usage : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 53)  then return "HDD usage : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 54)  then return "battery level : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 80)  then return "LLDP transmission interval : "..writeData(buffer, offset, "uint"):uint()
		elseif(eiID == 255) then return "vendor proprietary extension area : "..writeData(buffer, offset, "")
		else return "unknow ttc subtype : "..writeData(buffer, offset, "string"):string()
		end
	end

	--write　tlv head
	function writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
		local tlvHead = tlvTree:add(buffer(offset, 2), "TLV Head (type: " ..tlvType..", length: " ..tlvLen..")")
		tlvHead:add(buffer(offset, 1), "type: " ..tlvType)
		tlvHead:add(buffer(offset, 2), "length: " ..tlvLen)
	end

	--listLenAndList
	function setLenAndDataList(buffer, treeNode, offset, listName, dataType, elementLen)
		--list length
		local listLen = buffer(offset, 1):uint()
		treeNode:add(buffer(offset, 1), "number of "..listName..": "..listLen)
		offset = offset + 1
		--list
		local listTreeNode = treeNode:add(buffer(offset, listLen * elementLen), listName)
		local i = 0
		while( i ~= listLen) do
			listTreeNode:add(buffer(offset + i * elementLen, elementLen), " "..buffer(offset + i * elementLen, elementLen))
			i = i + 1
		end
	end


	function p_htip.dissector(buffer, pinfo, tree)
		
		-- local offset = 0
		local offset = 14
		
		local tlvType
		local tlvLen

		pinfo.cols.protocol:set("HTIP")
		pinfo.cols.info:set("Home-network Topology Identifying Protocol")


		tree:add(head_dest, buffer(0, 6))
		tree:add(head_sour, buffer(6, 6))
		tree:add(head_type, buffer(12, 2))

		local htipTree = tree:add(p_htip, buffer(14), "HTIP Protocol Data")

		
		while(tlvType ~= 0) do
			
			tlvType = bit32.rshift(buffer(offset, 1):uint(), 1)
	        --keep only the last 9 bits for the tlv lenght
	        tlvLen = bit32.band(buffer(offset, 2):uint(), 0x000001ff)
	        if(tlvType == 0) then
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "End Of LLDPDU TLV")
				
			elseif(tlvType == 1) then--chassis id
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "Chassis ID TLV (Chassis ID:"..buffer(offset + 2, 1):uint()..", MAC Address: " ..buffer(offset + 3, tlvLen -1)..")")
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, 1), "Chassis ID: " ..buffer(offset + 2, 1):uint())
				-- valueTree:add(buffer(offset + 3, tlvLen - 1), "MAC Address: " ..buffer(offset + 3, tlvLen -1))
				valueTree:add(mac_addr, buffer(offset + 3, tlvLen -1))
				
			elseif(tlvType == 2) then--prot id
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "Port ID TLV (Port ID subtype:"..buffer(offset + 2, 1):uint()..", port ID: " ..buffer(offset + 3, tlvLen -1)..")")
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, 1), "port ID subtype: " ..buffer(offset + 2, 1):uint())
				valueTree:add(buffer(offset + 3, tlvLen - 1), "port ID: " ..buffer(offset + 3, tlvLen -1))

			elseif(tlvType == 3) then--time to live
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "Time To Live TLV (Time To Live: " ..buffer(offset + 2, tlvLen)..")")
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, tlvLen), "Time To Live(TTL): " ..buffer(offset + 2, tlvLen))
				
			elseif(tlvType == 4) then--prot description
				local tlvTree
				if (buffer(offset +tlvLen +1, 1):string() == "\0") then
					tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "Port Description TLV (port description: " ..buffer(offset + 2, tlvLen -1):string()..")")
				else
					tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "Port Description TLV (port description: " ..buffer(offset + 2, tlvLen):string()..")")
				end
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, tlvLen), "port description: " ..buffer(offset + 2, tlvLen):string())
				
			--todo
			elseif(tlvType == 5) then--system name
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "System name (system name: " ..buffer(offset + 2, tlvLen)..")")
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, tlvLen), "system name: " ..buffer(offset + 2, tlvLen))
			
			--todo
			elseif(tlvType == 6) then--system description
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "System description TLV(system description: " ..buffer(offset + 2, tlvLen)..")")
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, tlvLen), "system description: " ..buffer(offset + 2, tlvLen))
			
			--todo
			elseif(tlvType == 7) then--syscapabilities
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "System capabilities TLV(system capabilities: " ..buffer(offset + 2, 2)..", enable capabilities: " ..buffer(offset + 4, 2)..")")
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, 2), "system capabilities: " ..buffer(offset + 2, 2))
				valueTree:add(buffer(offset + 4, 2), "enable capabilities: " ..buffer(offset + 4, 2))
			
			--todo
			elseif(tlvType == 8) then--mamnagement address
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "Management address TLV (value: " ..buffer(offset + 2, tlvLen)..")")
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, tlvLen), "value: " ..buffer(offset + 2, tlvLen))
				
			--main
			elseif(tlvType == 127) then--本番
				local ttcSubtype = buffer(offset + 5, 1):uint()
				local tlvTree
				if(ttcSubtype == 1) then
					tlvTree = htipTree:add(buffer(offset, tlvLen + 2), ttcSubtypeNameWrite(ttcSubtype).." TLV ("..eiIDNameWrite(buffer(offset + 6, 1):uint(), buffer, offset + 7)..")")
				else
					tlvTree = htipTree:add(buffer(offset, tlvLen + 2), ttcSubtypeNameWrite(ttcSubtype).." TLV")
				end
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, 3), "TTC OUI: " ..buffer(offset + 2, 3))
				valueTree:add(buffer(offset + 5, 1), "TTC Subtype: " ..ttcSubtype)
				
				--ttcSubtype番号により解析
				local temOffset = offset + 6
				if(ttcSubtype == 1) then--機器情報
					local ttcEITree = valueTree:add(buffer(temOffset, tlvLen - 4), "Equipment information")
					local eiID = buffer(temOffset, 1):uint()
					ttcEITree:add(buffer(temOffset, 1), "equipment information ID: " ..eiID)
					temOffset = temOffset + 1
					
					if(eiID == 1) then--区分****
						setLenAndData(buffer, ttcEITree, temOffset, "indicator", "string")
						
					elseif(eiID == 2) then--メーカコード**
						setLenAndData(buffer, ttcEITree, temOffset, "maker code", "string")
						
					elseif(eiID == 3) then--機種名**
						setLenAndData(buffer, ttcEITree, temOffset, "model name", "string")
						
					elseif(eiID == 4) then--型番****
						setLenAndData(buffer, ttcEITree, temOffset, "model number", "string")
						
					elseif(eiID == 20) then--チャンネル使用状態情報
						setLenAndData(buffer, ttcEITree, temOffset, "channel usage status", "uint")
						
					elseif(eiID == 21) then--電波強度情報
						setLenAndData(buffer, ttcEITree, temOffset, "radio wave intensity information", "uint")
						
					elseif(eiID == 22) then--通信エラー率情報
						setLenAndData(buffer, ttcEITree, temOffset, "communication error rate", "uint")
						
					elseif(eiID == 23) then--応答時間
						setLenAndData(buffer, ttcEITree, temOffset, "response time", "uint")
						
					elseif(eiID == 24) then--関連デバイス数
						setLenAndData(buffer, ttcEITree, temOffset, "number of related devices", "uint")
						
					elseif(eiID == 25) then--アクティブノード数
						setLenAndData(buffer, ttcEITree, temOffset, "number of active nodes", "uint")
						
					elseif(eiID == 26) then--無線品質
						setLenAndData(buffer, ttcEITree, temOffset, "radio quality", "uint")
						
					elseif(eiID == 27) then--再送数
						setLenAndData(buffer, ttcEITree, temOffset, "number of retransmissions", "uint")
						
					elseif(eiID == 50) then--ステータス情報
						setLenAndData(buffer, ttcEITree, temOffset, "status information", "string")
						
					elseif(eiID == 51) then--CPU使用率
						setLenAndData(buffer, ttcEITree, temOffset, "CPU usage", "uint")
						
					elseif(eiID == 52) then--メモリ使用率
						setLenAndData(buffer, ttcEITree, temOffset, "memory usage", "uint")
						
					elseif(eiID == 53) then--HDD使用率
						setLenAndData(buffer, ttcEITree, temOffset, "HDD usage", "uint")
						
					elseif(eiID == 54) then--バッテリ残量
						setLenAndData(buffer, ttcEITree, temOffset, "battery level", "uint")
						
					elseif(eiID == 80) then--LLDPDU送信間隔
						setLenAndData(buffer, ttcEITree, temOffset, "LLDP transmission interval", "uint")
						
					elseif(eiID == 255) then--ベンダ独自拡張領域
						--todo
					
					--[[
					elseif(eiID == 0 or (eiID >= 5 and eiID <= 19) or (eiID >= 28 and eiID <= 49) or (eiID >= 55 and eiID <= 79) or (eiID >= 81 and eiID <= 254))--予約領域
					then
					--]]
					else--ほか
						setLenAndData(buffer, ttcEITree, temOffset, "equipment information", "")
					end		
					
				elseif(ttcSubtype == 2) then--接続構成情報
					--文字で記述　実装していない
					temOffset = setLenAndData(buffer, valueTree, temOffset, "interface type", "uint")
					temOffset = setLenAndData(buffer, valueTree, temOffset, "port number", "uint")
					setLenAndDataList(buffer, valueTree, temOffset, "MAC Address List", "", 6)
					
				elseif(ttcSubtype == 3) then--MACアドレスリスト
					setLenAndDataList(buffer, valueTree, temOffset, "MAC Address List", "", 6)
					
				--[[
				elseif(ttcSubtype == 4)--拡張接続構成情報 --ドキュメントが間違ってる？フレーム構造のところにTTCSubtype=２と書いてる　--ドキュメント 6.3.5
				then 
				
				elseif(ttcSubtype == 5)--拡張MACアドレスリスト　--ドキュメントが間違ってる？フレーム構造のところにTTCSubtype=３と書いてる --ドキュメント 6.3.6
				then 
				--]]
				
				elseif(ttcSubtype == 6) then--設定情報
					--通信品質関連
					temOffset = setLenAndData(buffer, valueTree, temOffset, "Communication quality related information Sampling interval", "uint")
					temOffset = setLenAndData(buffer, valueTree, temOffset, "Communication quality related information Transmission interval", "uint")
					
					--端末品質関連
					temOffset = setLenAndData(buffer, valueTree, temOffset, "Terminal quality related information Sampling interval", "uint")
					temOffset = setLenAndData(buffer, valueTree, temOffset, "Terminal quality related information Transmission interval", "uint")
					
					--設定情報通知/更新結果
					valueTree:add(buffer(temOffset, 1), "Setting information notification / update result: "..buffer(temOffset, 1))
					
				--[[	
				elseif(ttcSubtype == 0 or (ttcSubtype >= 7 and ttcSubtype <= 255)) then--予約領域
					valueTree:add(buffer(offset + 6, tlvLen - 4), "Data: " ..buffer(offset + 6, tlvLen - 4))	
				--]]
				
				else--ほか
					valueTree:add(buffer(temOffset, tlvLen - 4), "Unkonwn Data: " ..buffer(temOffset, tlvLen - 4))
				
				end
				
			else--ほか
				local tlvTree = htipTree:add(buffer(offset, tlvLen + 2), "Unknown TLV")
				writeHead(buffer, offset, tlvTree, tlvType, tlvLen)
				local valueTree = tlvTree:add(buffer(offset + 2, tlvLen), "TLV Information String")
				valueTree:add(buffer(offset + 2, tlvLen), "value: " ..buffer(offset + 2, tlvLen))
				
			end
			
			offset = offset + tlvLen + 2
			
		end
	end

	local function is_htip_proto(buffer, pinfo, tree)
		if (buffer(12, 2):bytes() == ByteArray.new("88cc") and buffer(0, 6):bytes() == ByteArray.new("ffffffffffff")) then 
			p_htip.dissector(buffer, pinfo, tree)
			return true 
		end	
		return false
	end

	p_htip:register_heuristic("eth", is_htip_proto)
	
end