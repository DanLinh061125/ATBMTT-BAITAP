using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

// BÀI 1: AES-256-CBC (đối xứng). Mã hoá/giải mã file theo dạng stream => chạy được file hàng GB.
// Định dạng file mã hoá: [16 byte IV][dữ liệu mã hoá]  (IV ngẫu nhiên mỗi lần mã hoá)
class Program
{
    const int BufSize = 1 << 22; // 4 MB
    static byte[]? key;

    static string Ask(string msg) { Console.Write(msg); return (Console.ReadLine() ?? "").Trim().Trim('"'); }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;
        while (true)
        {
            Console.WriteLine($"\n===== AES-CBC =====  Khoá: {(key == null ? "chưa có" : key.Length * 8 + " bit")}");
            Console.WriteLine("1. Sinh khoá AES-256\n2. Lưu khoá ra file\n3. Nạp khoá từ file\n4. Mã hoá / giải mã văn bản\n5. Mã hoá file\n6. Giải mã file\n7. So sánh 2 file theo byte\n8. Tạo file test dung lượng lớn\n9. Thử nghiệm tự động (mã hoá + giải mã + so sánh)\n0. Thoát");
            try
            {
                switch (Ask("Chọn: "))
                {
                    case "1": key = RandomNumberGenerator.GetBytes(32); Console.WriteLine("Khoá (base64): " + Convert.ToBase64String(key)); break;
                    case "2": File.WriteAllText(Ask("File lưu khoá: "), Convert.ToBase64String(RequireKey())); Console.WriteLine("Đã lưu."); break;
                    case "3": LoadKey(Ask("File khoá: ")); break;
                    case "4": TextMenu(); break;
                    case "5": EncryptFile(Ask("File nguồn: "), Ask("File đầu ra: ")); break;
                    case "6": DecryptFile(Ask("File đã mã hoá: "), Ask("File đầu ra: ")); break;
                    case "7": CompareFiles(Ask("File A: "), Ask("File B: ")); break;
                    case "8": MakeTestFile(Ask("Đường dẫn file: "), long.Parse(Ask("Dung lượng (MB): "))); break;
                    case "9": AutoTest(Ask("File nguồn: ")); break;
                    case "0": return;
                }
            }
            catch (Exception ex) { Console.WriteLine("Lỗi: " + ex.Message); }
        }
    }

    static byte[] RequireKey() => key ?? throw new Exception("Chưa có khoá. Hãy sinh (1) hoặc nạp (3) khoá.");

    static void LoadKey(string path)
    {
        var k = Convert.FromBase64String(File.ReadAllText(path).Trim());
        if (k.Length is not (16 or 24 or 32)) throw new Exception("Khoá phải dài 16/24/32 byte.");
        key = k;
        Console.WriteLine($"Đã nạp khoá {k.Length * 8} bit.");
    }

    static void TextMenu()
    {
        var k = RequireKey();
        using var aes = Aes.Create();
        aes.Key = k;
        if (Ask("1 = mã hoá, 2 = giải mã: ") == "1")
        {
            aes.GenerateIV();
            var ct = aes.EncryptCbc(Encoding.UTF8.GetBytes(Ask("Văn bản: ")), aes.IV);
            Console.WriteLine("Kết quả (base64 của IV+ciphertext):\n" + Convert.ToBase64String(aes.IV.Concat(ct).ToArray()));
        }
        else
        {
            var all = Convert.FromBase64String(Ask("Chuỗi base64: "));
            var pt = aes.DecryptCbc(all.AsSpan(16), all.AsSpan(0, 16));
            Console.WriteLine("Bản rõ: " + Encoding.UTF8.GetString(pt));
        }
    }

    static TimeSpan EncryptFile(string src, string dst)
    {
        var k = RequireKey();
        using var aes = Aes.Create();
        aes.Key = k; aes.GenerateIV();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        var sw = Stopwatch.StartNew();
        fout.Write(aes.IV);
        using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
        fin.CopyTo(cs, BufSize);
        cs.FlushFinalBlock();
        sw.Stop();
        Report("Mã hoá", fin.Length, sw.Elapsed);
        return sw.Elapsed;
    }

    static TimeSpan DecryptFile(string src, string dst)
    {
        var k = RequireKey();
        using var aes = Aes.Create();
        aes.Key = k;
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        var sw = Stopwatch.StartNew();
        var iv = new byte[16];
        fin.ReadExactly(iv);
        aes.IV = iv;
        using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
        cs.CopyTo(fout, BufSize);
        fout.Flush();
        sw.Stop();
        Report("Giải mã", fout.Length, sw.Elapsed);
        return sw.Elapsed;
    }

    static void Report(string what, long bytes, TimeSpan t) =>
        Console.WriteLine($"{what}: {bytes / 1048576.0:N1} MB trong {t.TotalSeconds:N2} s  ({bytes / 1048576.0 / t.TotalSeconds:N1} MB/giay)");

    static int ReadFull(Stream s, byte[] buf)
    {
        int total = 0, n;
        while (total < buf.Length && (n = s.Read(buf, total, buf.Length - total)) > 0) total += n;
        return total;
    }

    static bool CompareFiles(string a, string b)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize);
        var sw = Stopwatch.StartNew();
        if (fa.Length != fb.Length)
        {
            Console.WriteLine($"KHÁC kích thước: {fa.Length} vs {fb.Length} byte");
            return false;
        }
        var ba = new byte[BufSize]; var bb = new byte[BufSize];
        long pos = 0;
        while (true)
        {
            int n = ReadFull(fa, ba), m = ReadFull(fb, bb);
            if (n != m) { Console.WriteLine("KHÁC nhau (độ dài đọc)."); return false; }
            if (n == 0) break;
            if (!ba.AsSpan(0, n).SequenceEqual(bb.AsSpan(0, n)))
            {
                int i = ba.AsSpan(0, n).CommonPrefixLength(bb.AsSpan(0, n));
                Console.WriteLine($"KHÁC tại byte thứ {pos + i}");
                return false;
            }
            pos += n;
        }
        Console.WriteLine($"GIỐNG NHAU hoàn toàn ({pos} byte) - so sánh mất {sw.Elapsed.TotalSeconds:N2} s");
        return true;
    }

    static void MakeTestFile(string path, long mb)
    {
        var buf = new byte[BufSize];
        using var f = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        for (long i = 0; i < mb; i++) { RandomNumberGenerator.Fill(buf); f.Write(buf); }
        Console.WriteLine($"Đã tạo {path} ({mb} MB).");
    }

    static void AutoTest(string src)
    {
        string enc = src + ".enc", dec = src + ".dec";
        var te = EncryptFile(src, enc);
        var td = DecryptFile(enc, dec);
        bool ok = CompareFiles(src, dec);
        long size = new FileInfo(src).Length, esize = new FileInfo(enc).Length;
        Console.WriteLine("\n--- TỔNG KẾT ---");
        Console.WriteLine($"Kích thước nguồn : {size:N0} byte");
        Console.WriteLine($"Kích thước mã hoá: {esize:N0} byte (+{esize - size} byte: IV + padding)");
        Console.WriteLine($"Thời gian mã hoá : {te.TotalSeconds:N2} s");
        Console.WriteLine($"Thời gian giải mã: {td.TotalSeconds:N2} s");
        Console.WriteLine($"Kết quả so sánh  : {(ok ? "ĐÚNG" : "SAI")}");
    }
}
