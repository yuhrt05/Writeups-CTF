# UTCTF 2026 - Forensics


![UTCTF_2026](https://hackmd.io/_uploads/SJtUW3PpWl.png)


![image](https://hackmd.io/_uploads/Hyrao2b9Zg.png)

Long time no CTF =))

## Half Awake
![image](https://hackmd.io/_uploads/ByLuh3Wcbl.png)

Có được hint khá rõ ràng trong pcap, flag được xor với key.version của mDNS

![image](https://hackmd.io/_uploads/B1ihhhZ9Zl.png)


![image](https://hackmd.io/_uploads/SJbHJTWqZx.png)

key.version là `0x7b`

Follow theo TCP stream dump được PK về

![image](https://hackmd.io/_uploads/H13mp2Zc-x.png)

Các chấm đỏ là dữ liệu đang bị mã hóa, lấy file này xor với 0x7b là ra

![image](https://hackmd.io/_uploads/r1r61p-qWx.png)

Có thể thấy được flag được so le nhau

![image](https://hackmd.io/_uploads/SJGbxTb9be.png)

`flag:utflag{h4lf_aw4k3_s33_th3_pr0t0c0l_tr1ck}`

## Cold Workspace

![image](https://hackmd.io/_uploads/r17rgpb5Zl.png)

Strings thôi là có được hết dữ kiện

![image](https://hackmd.io/_uploads/HkOpepZcWe.png)

![image](https://hackmd.io/_uploads/BktmWab9Ze.png)

Lấy ENCD đi decrypt cùng key là ENCK và iv là ENCV

![image](https://hackmd.io/_uploads/BkycbpZ5Wg.png)

`flag:utflag{m3m0ry_r3t41ns_wh4t_d1sk_l053s}`

## Last Byte Standing

![image](https://hackmd.io/_uploads/B1xVMabcZl.png)

DNS Exfiltration

![image](https://hackmd.io/_uploads/SkT3GaW9bg.png)

`tshark -r last-byte-standing.pcap -Y "dns.extraneous.data" -T fields -e dns.extraneous.data | tr -d ':\n' | sed 's/30/0/g; s/31/1/g'`

![image](https://hackmd.io/_uploads/ByCH7pW9Wx.png)

## Silent Archive

![image](https://hackmd.io/_uploads/ByNsmTWcZl.png)

Bài cho 2 file tar, một file có 999 file tar con bên trong lồng nhau

```bash
i=999; while [ -f "$i.tar" ]; do tar -xf "$i.tar" && echo "Xong $i.tar"; ((i--)); done
```

giải mã đến file 1.tar thì cần pass, pass sẽ trích xuất từ file tar còn lại chứa 2 ảnh trông giống hệt nhau nhưng khác biệt nằm ở AUTH_FRAGMENT_B64

![image](https://hackmd.io/_uploads/ry1cB6W9We.png)
![image](https://hackmd.io/_uploads/Sklir6WqZe.png)


decode b64 tương ứng thì cái thứ 2 là pass của 1.tar. Dễ dàng nhận thấy đây là Whitespace Stegano

![image](https://hackmd.io/_uploads/S1i4Uab5be.png)

```python!
python3 -c "print(''.join(chr(int(line.replace(' ', '0').replace('\t', '1'), 2)) for line in open('NotaFlag.txt').read().splitlines() if line))"
```

![image](https://hackmd.io/_uploads/S1pw8aW5Zl.png)

## Landfall

![image](https://hackmd.io/_uploads/SJcc8abcZl.png)


![image](https://hackmd.io/_uploads/ByhNPT-5Zg.png)

Trong `console_history.txt` của powershell

![image](https://hackmd.io/_uploads/rkb3Dpb5bx.png)

Lấy md5sum để unzip checkpointA

![image](https://hackmd.io/_uploads/S1PldaWqbl.png)

FLAG

![image](https://hackmd.io/_uploads/ByZ4d6-q-l.png)


## Watson
![image](https://hackmd.io/_uploads/HkAh8p-9-e.png)

Mô tả để unzip 2 checkpoint A B

![image](https://hackmd.io/_uploads/B1gs_pWqZg.png)

### Checkpoint A:

Delete file mà muốn khôi phục thì ưu tiên check trong RecycleBin

![image](https://hackmd.io/_uploads/BJ4_Yab5bg.png)

![image](https://hackmd.io/_uploads/H1N5FTZcZg.png)

=> pass: HOOKEM

### Checkpoint B:

Check trong Amcache.hve, dùng AppCompatCacheParser.exe parse ra csv rồi đọc thấy `calc.exe` nghi ngờ nhất

![image](https://hackmd.io/_uploads/SkGOc6W9Wx.png)

Lấy hash của nó unzip ra là có flag

## Sherlockk
![image](https://hackmd.io/_uploads/HJta8pZqbe.png)

Quá lười để làm lại

![image](https://hackmd.io/_uploads/Sk3C7CBcbg.png)

### Checkpoint A

Kiểm tra `history` Chrome của Admin là ra link pastebin

### Checkpoint B

Mở `$MFT` bằng `MFTExpolrer` đọc được file Administrators-Notes hay gì đó đã bị xóa.

### Checkpoint C

Trong download của admin thì có tải 1 script.sh.sh trong lõi là `LinPEAS`. Lấy MD5 là done

FLAG
`utflag{b45k3rv1ll3-3l3m3n74ry-4r7hur_c0n4n_d0yl3}`
