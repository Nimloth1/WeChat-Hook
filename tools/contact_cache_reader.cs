// Windows read-only contact-cache candidate reader. No target code execution or database access.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace ContactCacheReadOnly {
    public sealed class Candidate {
        public string ID;
        public string Name;
        public string Kind;
        public bool StableSample;
        public bool IdentityConfirmed = false;
    }
    public sealed class Observation {
        public int ProcessId;
        public long BytesRead;
        public long EligibleBytes;
        public int ReadFailures;
        public int DistinctIDStrings;
        public bool Complete = false; // Heap scanning cannot establish a complete contact list.
        public string StopReason;
        public List<Candidate> Candidates = new List<Candidate>();
    }
    public static class Reader {
        [StructLayout(LayoutKind.Sequential)]
        struct Region {
            public IntPtr BaseAddress, AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State, Protect, Type;
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out Region info, UIntPtr length);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr size, out UIntPtr read);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder name,ref uint size);

        const long TotalBudget = 512L * 1024 * 1024;
        const long PassBudget = 240L * 1024 * 1024;
        const int Chunk = 1024 * 1024;
        const int Overlap = 512;
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        static readonly Regex IDPattern = new Regex(@"(?<![A-Za-z0-9_])(?:wxid_[A-Za-z0-9_]{4,64}|[0-9]{5,24}@chatroom)(?![A-Za-z0-9_@])",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        static readonly Regex WholeID = new Regex(@"\A(?:wxid_[A-Za-z0-9_]{4,64}|[0-9]{5,24}@chatroom)\z",
            RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        sealed class Session : IDisposable {
            public readonly Observation Result = new Observation();
            readonly IntPtr process;
            readonly Stopwatch time = Stopwatch.StartNew();
            public Session(int pid,long expectedCreation) {
                if(Environment.GetEnvironmentVariable("COMPUTERNAME") != "VW12") throw new InvalidOperationException("VW12 only");
                using(var p=Process.GetProcessById(pid)) {
                    if(!String.Equals(p.ProcessName,"Weixin",StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Wrong process");
                }
                process=OpenProcess(0x410,false,pid); // QUERY_INFORMATION | VM_READ only.
                if(process==IntPtr.Zero) throw new InvalidOperationException("Read-only OpenProcess failed: "+Marshal.GetLastWin32Error());
                long created,exited,kernel,user;
                var path=new StringBuilder(1024); uint size=1024;
                if(!GetProcessTimes(process,out created,out exited,out kernel,out user) || created!=expectedCreation
                    || !QueryFullProcessImageName(process,0,path,ref size)
                    || !String.Equals(path.ToString(),@"C:\Program Files\Tencent\Weixin\Weixin.exe",StringComparison.OrdinalIgnoreCase)) {
                    CloseHandle(process);
                    throw new InvalidOperationException("Target handle identity changed; no memory read");
                }
                Result.ProcessId=pid;
            }
            public void Dispose() { CloseHandle(process); }
            void Budget(int count) {
                if(time.Elapsed.TotalSeconds>45) throw new InvalidOperationException("time_budget_reached");
                if(count<0 || Result.BytesRead+count>TotalBudget) throw new InvalidOperationException("byte_budget_reached");
            }
            byte[] Read(ulong address,int count) {
                Budget(count);
                if(address<65536 || address>0x7FFFFFFEFFFFUL || address+(ulong)count>0x7FFFFFFF0000UL) return null;
                var data=new byte[count]; UIntPtr got;
                bool ok=ReadProcessMemory(process,new IntPtr((long)address),data,(UIntPtr)count,out got);
                Result.BytesRead+=(long)got.ToUInt64();
                if(!ok || got.ToUInt64()!=(ulong)count) { ++Result.ReadFailures; return null; }
                return data;
            }
            static ulong U64(byte[] data,int offset) { return BitConverter.ToUInt64(data,offset); }
            string NativeString(ulong address,int limit) {
                var before=Read(address,32);
                if(before==null) return null;
                ulong size=U64(before,16),capacity=U64(before,24);
                if(size>(ulong)limit || capacity<size || capacity>8192) return null;
                if(capacity<16 && size>15) return null;
                ulong chars=capacity>=16 ? U64(before,0) : address;
                var data=Read(chars,(int)size+1);
                var after=Read(address,32);
                if(data==null || after==null || data[(int)size]!=0 || !Equal(before,after)) return null;
                try {
                    string text=Utf8.GetString(data,0,(int)size);
                    if(text.IndexOf('\0')>=0 || text.IndexOf('\r')>=0 || text.IndexOf('\n')>=0) return null;
                    return text;
                } catch(DecoderFallbackException) { return null; }
            }
            static bool Equal(byte[] a,byte[] b) {
                if(a.Length!=b.Length) return false;
                for(int i=0;i<a.Length;++i) if(a[i]!=b[i]) return false;
                return true;
            }
            void CandidateAt(ulong header,string expected) {
                // Reference 4.1.10.27 Contact record: username@+0x08, nickname@+0xD8.
                // The scan finds an address, not an owned object. Read via the OS only;
                // never pass this address to WeChat/SQLite or claim current membership.
                if(header<65536 || (header&7)!=0) return;
                string id=NativeString(header,128);
                if(id==null || id!=expected || !WholeID.IsMatch(id)) return;
                string name=NativeString(header+0xD0,512);
                if(String.IsNullOrEmpty(name) || name.StartsWith("http",StringComparison.OrdinalIgnoreCase)) return;
                string idAgain=NativeString(header,128),nameAgain=NativeString(header+0xD0,512);
                if(idAgain!=id || nameAgain!=name) return;
                foreach(var item in Result.Candidates) if(item.ID==id && item.Name==name) return;
                if(Result.Candidates.Count>=32) throw new InvalidOperationException("candidate_budget_reached");
                Result.Candidates.Add(new Candidate { ID=id,Name=name,Kind=id.EndsWith("@chatroom",StringComparison.Ordinal)?"group_candidate":"person_candidate",StableSample=true });
            }
            List<Region> Regions() {
                var result=new List<Region>();
                ulong address=65536;
                int examined=0;
                while(address<0x7FFFFFFF0000UL) {
                    Budget(0);
                    if(++examined>40000) throw new InvalidOperationException("region_budget_reached");
                    Region r;
                    if(VirtualQueryEx(process,new IntPtr((long)address),out r,(UIntPtr)Marshal.SizeOf(typeof(Region)))==UIntPtr.Zero) break;
                    ulong start=(ulong)r.BaseAddress.ToInt64(),size=r.RegionSize.ToUInt64();
                    if(size==0 || start+size<=address) throw new InvalidOperationException("invalid_region");
                    // Only committed, private, non-executable readable heap pages; no images or mappings.
                    uint p=r.Protect&0xFF;
                    if(r.State==0x1000 && r.Type==0x20000 && (r.Protect&0x100)==0 && (p==2 || p==4 || p==8)) {
                        result.Add(r); Result.EligibleBytes+=(long)size;
                    }
                    address=start+size;
                }
                return result;
            }
            bool Walk(List<Region> regions,Action<ulong,byte[]> inspect) {
                long pass=0;
                foreach(var r in regions) {
                    ulong start=(ulong)r.BaseAddress.ToInt64(),size=r.RegionSize.ToUInt64();
                    for(ulong offset=0;offset<size;) {
                        int count=(int)Math.Min((ulong)Chunk,size-offset);
                        if(pass+count>PassBudget) return false;
                        var data=Read(start+offset,count); pass+=count;
                        if(data!=null) inspect(start+offset,data);
                        if(offset+(ulong)count>=size) break;
                        offset+=(ulong)(count-Overlap);
                    }
                }
                return true;
            }
            public Observation Run() {
                var strings=new Dictionary<ulong,string>();
                var distinct=new HashSet<string>();
                try {
                    var regions=Regions();
                    bool firstComplete=Walk(regions,delegate(ulong start,byte[] data) {
                        // Latin-1 preserves byte offsets; it is only a transient regex buffer.
                        string text=Encoding.GetEncoding(28591).GetString(data);
                        foreach(Match match in IDPattern.Matches(text)) {
                            ulong address=start+(ulong)match.Index;
                            if(strings.ContainsKey(address)) continue;
                            if(strings.Count>=4096 || distinct.Count>=256) throw new InvalidOperationException("ID_string_budget_reached");
                            strings.Add(address,match.Value); distinct.Add(match.Value);
                            if(match.Length<16) CandidateAt(address,match.Value);
                        }
                    });
                    Result.DistinctIDStrings=distinct.Count;
                    bool secondComplete=Walk(regions,delegate(ulong start,byte[] data) {
                        for(int i=(int)((8-(start&7))&7);i+32<=data.Length;i+=8) {
                            string expected;
                            if(strings.TryGetValue(U64(data,i),out expected)) CandidateAt(start+(ulong)i,expected);
                        }
                    });
                    Result.StopReason=firstComplete && secondComplete ? "bounded_passes_finished_candidates_not_authoritative" : "partial_pass_budget_candidates_not_authoritative";
                } catch(InvalidOperationException error) { Result.StopReason=error.Message; }
                Result.DistinctIDStrings=distinct.Count;
                return Result;
            }
        }
        public static Observation Scan(int processId,long expectedCreation) { using(var session=new Session(processId,expectedCreation)) return session.Run(); }
    }
}
