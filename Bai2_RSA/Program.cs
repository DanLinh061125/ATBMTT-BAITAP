using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

// BÀI 2: RSA, PEM, SHA-256, chữ ký số (PKCS#1 v1.5 xác định  vs  PSS ngẫu nhiên)
class Program
{
    static string Ask(string msg) { Console.Write(msg); return (Console.ReadLine() ?? "").Trim().Trim('"'); }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;
        while (true)
        {
            Console.WriteLine("\n===== RSA =====\n1. Sinh cặp khoá + xuất PEM\n2. Xem PEM (hex + cấu trúc ASN.1/DER)\n3. Nhập PEM -> n, e (và d, p, q... nếu là private)\n4. Mã hoá (RSA-OAEP, <= 190 byte với khoá 2048)\n5. Giải mã + so sánh với bản gốc\n6. Đo tốc độ mã hoá / giải mã\n7. Băm SHA-256 + đánh giá hiệu ứng thác (avalanche)\n8. Chữ ký số: xác định vs ngẫu nhiên (PSS / nonce)\n0. Thoát");
            try
            {
                switch (Ask("Chọn: "))
                {
                    case "1": GenKeys(); break;
                    case "2": ViewPem(Ask("File PEM: ")); break;
                    case "3": ImportPem(Ask("File PEM: ")); break;
                    case "4": Encrypt(); break;
                    case "5": Decrypt(); break;
                    case "6": Benchmark(); break;
                    case "7": HashDemo(); break;
                    case "8": SignDemo(); break;
                    case "0": return;
                }
            }
            catch (Exception ex) { Console.WriteLine("Lỗi: " + ex.Message); }
        }
    }

    static RSA LoadPem(string path) { var r = RSA.Create(); r.ImportFromPem(File.ReadAllText(path)); return r; }

    // ---------- 1. Sinh khoá ----------
    static void GenKeys()
    {
        string s = Ask("Độ dài khoá (bit) [2048]: ");
        int size = s == "" ? 2048 : int.Parse(s);
        using var rsa = RSA.Create(size);
        File.WriteAllText("public.pem", rsa.ExportSubjectPublicKeyInfoPem());   // BEGIN PUBLIC KEY  (X.509 SPKI)
        File.WriteAllText("private.pem", rsa.ExportPkcs8PrivateKeyPem());       // BEGIN PRIVATE KEY (PKCS#8)
        Console.WriteLine($"Đã tạo public.pem, private.pem ({size} bit)");
    }

    // ---------- 2. Xem PEM ----------
    static void ViewPem(string path)
    {
        var lines = File.ReadAllLines(path);
        Console.WriteLine("Dòng đầu/cuối (nhãn): " + lines[0] + "  ...  " + lines[^1]);
        var der = Convert.FromBase64String(string.Concat(lines.Where(l => !l.StartsWith("-----"))));
        Console.WriteLine($"\nPhần base64 giải mã ra {der.Length} byte DER. Hex dump:");
        for (int i = 0; i < der.Length; i += 16)
            Console.WriteLine($"{i:X4}  {Convert.ToHexString(der.AsSpan(i, Math.Min(16, der.Length - i)))}");
        Console.WriteLine("\nCấu trúc ASN.1 / DER (tag - length - value):");
        DumpDer(der, 0, der.Length, 0);
    }

    static void DumpDer(byte[] d, int start, int end, int depth)
    {
        int i = start;
        while (i < end)
        {
            int tagPos = i;
            byte tag = d[i++];
            int len = d[i++], hdr = 2;
            if ((len & 0x80) != 0)               // length dạng dài: byte đầu = 0x80 + số byte độ dài
            {
                int nb = len & 0x7F; len = 0;
                for (int k = 0; k < nb; k++) len = (len << 8) | d[i++];
                hdr = 2 + nb;
            }
            string name = tag switch { 0x30 => "SEQUENCE", 0x02 => "INTEGER", 0x05 => "NULL", 0x06 => "OID", 0x03 => "BIT STRING", 0x04 => "OCTET STRING", _ => "?" };
            Console.Write($"{new string(' ', depth * 2)}@{tagPos,4}: tag={tag:X2} {name}, len={len}, header={hdr}B");
            switch (tag)
            {
                case 0x30: Console.WriteLine(); DumpDer(d, i, i + len, depth + 1); break;
                case 0x03: Console.WriteLine($", unused bits={d[i]}"); DumpDer(d, i + 1, i + len, depth + 1); break;
                case 0x04:
                    if (len > 0 && d[i] == 0x30) { Console.WriteLine(" -> chứa DER lồng bên trong"); DumpDer(d, i, i + len, depth + 1); }
                    else Console.WriteLine();
                    break;
                case 0x02:
                    string hex = Convert.ToHexString(d.AsSpan(i, Math.Min(len, 12))) + (len > 12 ? "..." : "");
                    Console.WriteLine($", value={hex}" + (len > 1 && d[i] == 0 ? "  (00 đứng đầu để số không bị hiểu là âm)" : ""));
                    break;
                case 0x06: Console.WriteLine(" = " + Oid(d, i, len)); break;
                default: Console.WriteLine(); break;
            }
            i += len;
        }
    }

    static string Oid(byte[] d, int pos, int len)
    {
        var parts = new List<string> { (d[pos] / 40).ToString(), (d[pos] % 40).ToString() };
        long v = 0;
        for (int i = pos + 1; i < pos + len; i++)
        {
            v = (v << 7) | (uint)(d[i] & 0x7F);
            if ((d[i] & 0x80) == 0) { parts.Add(v.ToString()); v = 0; }
        }
        string oid = string.Join(".", parts);
        return oid + (oid == "1.2.840.113549.1.1.1" ? " (rsaEncryption)" : "");
    }

    // ---------- 3. Nhập PEM ----------
    static void ImportPem(string path)
    {
        using var rsa = LoadPem(path);
        RSAParameters p;
        bool priv = true;
        try { p = rsa.ExportParameters(true); } catch (CryptographicException) { p = rsa.ExportParameters(false); priv = false; }
        Console.WriteLine(priv ? "== PRIVATE KEY ==" : "== PUBLIC KEY ==");
        Show("n (Modulus)", p.Modulus); Show("e (Exponent)", p.Exponent);
        if (priv)
        {
            Show("d (PrivateExponent)", p.D); Show("p", p.P); Show("q", p.Q);
            Show("dp = d mod (p-1)", p.DP); Show("dq = d mod (q-1)", p.DQ); Show("qInv = q^-1 mod p", p.InverseQ);
        }
    }

    static void Show(string name, byte[]? v)
    {
        if (v == null) return;
        var bi = new BigInteger(v, true, true);
        Console.WriteLine($"{name}: {bi.GetBitLength()} bit" + (v.Length <= 4 ? $" = {bi}" : ""));
        Console.WriteLine("  hex: " + Convert.ToHexString(v));
    }

    // ---------- 4. Mã hoá ----------
    static void Encrypt()
    {
        using var rsa = LoadPem(Ask("File PEM (public hoặc private): "));
        int max = rsa.KeySize / 8 - 2 * 32 - 2;   // OAEP-SHA256: k - 2*hLen - 2 (2048 bit -> 190)
        Console.WriteLine($"Khoá {rsa.KeySize} bit -> tối đa {max} byte.");
        byte[] data;
        switch (Ask("Dữ liệu: 1 = nhập text, 2 = đọc file, 3 = khoá AES-256 ngẫu nhiên (32 byte): "))
        {
            case "1": data = Encoding.UTF8.GetBytes(Ask("Text: ")); break;
            case "2": data = File.ReadAllBytes(Ask("File: ")); break;
            default: data = RandomNumberGenerator.GetBytes(32); Console.WriteLine("AES key (base64): " + Convert.ToBase64String(data)); break;
        }
        if (data.Length > max) throw new Exception($"Dữ liệu {data.Length} byte > {max} byte.");
        File.WriteAllBytes("plain.bin", data);
        var ct = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        File.WriteAllText("cipher.b64", Convert.ToBase64String(ct));
        Console.WriteLine($"Đã lưu cipher.b64 ({ct.Length} byte mã hoá) và plain.bin (bản gốc để so sánh).");
    }

    // ---------- 6. Giải mã ----------
    static void Decrypt()
    {
        using var rsa = LoadPem(Ask("File private PEM: "));
        var ct = Convert.FromBase64String(File.ReadAllText(Ask("File chứa base64 đã mã hoá: ")).Trim());
        var pt = rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);
        Console.WriteLine($"Giải mã được {pt.Length} byte: {Convert.ToBase64String(pt)}");
        string orig = Ask("File bản gốc để so sánh (Enter = bỏ qua): ");
        if (orig != "")
            Console.WriteLine(pt.AsSpan().SequenceEqual(File.ReadAllBytes(orig)) ? "=> GIỐNG bản gốc." : "=> KHÁC bản gốc!");
    }

    // ---------- 7. Tốc độ ----------
    static void Benchmark()
    {
        var data = RandomNumberGenerator.GetBytes(32);
        Console.WriteLine("A) API RSA của .NET, OAEP-SHA256, dữ liệu 32 byte (mã hoá = public key, giải mã = private key)");
        foreach (int bits in new[] { 1024, 2048, 3072, 4096 })
        {
            using var full = RSA.Create(bits);
            using var pub = RSA.Create();
            pub.ImportParameters(full.ExportParameters(false));
            int ne = 500, nd = 100;
            var sw = Stopwatch.StartNew();
            byte[] ct = null!;
            for (int i = 0; i < ne; i++) ct = pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            double te = sw.Elapsed.TotalMilliseconds / ne;
            sw.Restart();
            for (int i = 0; i < nd; i++) full.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);
            double td = sw.Elapsed.TotalMilliseconds / nd;
            Console.WriteLine($"  {bits,5} bit: mã hoá {te,8:N4} ms | giải mã {td,8:N4} ms | giải mã chậm gấp {td / te:N1} lần");
        }

        Console.WriteLine("\nB) 'RSA thô' bằng BigInteger.ModPow: m^e mod n (e bé) so với m^d mod n (d lớn bằng n) - không dùng CRT");
        foreach (int bits in new[] { 1024, 2048, 4096 })
        {
            using var rsa = RSA.Create(bits);
            var p = rsa.ExportParameters(true);
            BigInteger n = new(p.Modulus!, true, true), e = new(p.Exponent!, true, true), d = new(p.D!, true, true);
            BigInteger m = new BigInteger(RandomNumberGenerator.GetBytes(32), true, true);
            int ne = 2000, nd = 50;
            var sw = Stopwatch.StartNew();
            BigInteger c = 0;
            for (int i = 0; i < ne; i++) c = BigInteger.ModPow(m, e, n);
            double te = sw.Elapsed.TotalMilliseconds / ne;
            sw.Restart();
            for (int i = 0; i < nd; i++) BigInteger.ModPow(c, d, n);
            double td = sw.Elapsed.TotalMilliseconds / nd;
            Console.WriteLine($"  {bits,5} bit: e={e} ({e.GetBitLength()} bit) {te,8:N4} ms | d ({d.GetBitLength()} bit) {td,8:N3} ms | tỉ lệ {td / te:N0}x");
        }
    }

    // ---------- 8. SHA-256 ----------
    static void HashDemo()
    {
        byte[]? prev = null;
        Console.WriteLine("Nhập chuỗi (rỗng để thoát). Thử đổi 1 ký tự, thêm 1 dấu cách, đổi hoa/thường...");
        while (true)
        {
            string s = Ask("\nChuỗi: ");
            if (s == "") break;
            var h = SHA256.HashData(Encoding.UTF8.GetBytes(s));
            Console.WriteLine("SHA-256: " + Convert.ToHexString(h).ToLower());
            if (prev != null)
            {
                int diff = 0;
                for (int i = 0; i < 32; i++) diff += BitOperations.PopCount((uint)(h[i] ^ prev[i]));
                Console.WriteLine($"So với lần trước: {diff}/256 bit khác = {diff / 2.56:N1}%  (lý tưởng ~50%)");
            }
            prev = h;
        }
        // Thống kê tự động: đổi đúng 1 bit đầu vào, lặp 2000 lần
        int total = 0, N = 2000;
        for (int t = 0; t < N; t++)
        {
            var x = RandomNumberGenerator.GetBytes(64);
            var y = (byte[])x.Clone();
            y[RandomNumberGenerator.GetInt32(64)] ^= (byte)(1 << RandomNumberGenerator.GetInt32(8));
            var a = SHA256.HashData(x); var b = SHA256.HashData(y);
            for (int i = 0; i < 32; i++) total += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        }
        Console.WriteLine($"\nThống kê: đổi 1 bit đầu vào, {N} lần -> trung bình {total / (double)N:N1}/256 bit đầu ra thay đổi ({total / (double)N / 2.56:N1}%).");
    }

    // ---------- 9. Chữ ký số ----------
    static void SignDemo()
    {
        using var priv = LoadPem(Ask("File private PEM: "));
        using var pub = RSA.Create();
        pub.ImportParameters(priv.ExportParameters(false));
        var data = Encoding.UTF8.GetBytes(Ask("Dữ liệu cần ký: "));
        var sha = HashAlgorithmName.SHA256;

        Console.WriteLine("\n[1] RSA PKCS#1 v1.5 (xác định): ký 3 lần");
        var first = priv.SignData(data, sha, RSASignaturePadding.Pkcs1);
        for (int i = 0; i < 3; i++)
        {
            var s = priv.SignData(data, sha, RSASignaturePadding.Pkcs1);
            Console.WriteLine($"  lần {i + 1}: {Convert.ToBase64String(s)[..40]}...  giống lần đầu: {s.AsSpan().SequenceEqual(first)}  verify: {pub.VerifyData(data, s, sha, RSASignaturePadding.Pkcs1)}");
        }

        Console.WriteLine("\n[2] RSA-PSS (salt ngẫu nhiên): ký 3 lần");
        var prevS = Array.Empty<byte>();
        for (int i = 0; i < 3; i++)
        {
            var s = priv.SignData(data, sha, RSASignaturePadding.Pss);
            Console.WriteLine($"  lần {i + 1}: {Convert.ToBase64String(s)[..40]}...  giống lần trước: {s.AsSpan().SequenceEqual(prevS)}  verify: {pub.VerifyData(data, s, sha, RSASignaturePadding.Pss)}");
            prevS = s;
        }

        Console.WriteLine("\n[3] Nonce: ký SHA256(data || nonce), gửi kèm nonce");
        for (int i = 0; i < 3; i++)
        {
            var nonce = RandomNumberGenerator.GetBytes(16);
            var msg = data.Concat(nonce).ToArray();
            var s = priv.SignData(msg, sha, RSASignaturePadding.Pkcs1);
            Console.WriteLine($"  lần {i + 1}: nonce={Convert.ToHexString(nonce)[..8]}.. sig={Convert.ToBase64String(s)[..40]}...  verify: {pub.VerifyData(msg, s, sha, RSASignaturePadding.Pkcs1)}");
        }
    }
}
