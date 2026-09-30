using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Argon2DotnetFast.Internal;

// The blocks, then one scratch area per execution thread. One allocation, so one wipe covers all.
internal sealed unsafe class Arena : SafeHandleZeroOrMinusOneIsInvalid
{
    private readonly long blockBytes;
    private readonly long length;
    private IntPtr allocation;

    // touch: false leaves the blocks to fault in during the fill, which writes every block before it
    // reads it; the scratch areas, which hold the address generator's zero block, are cleared anyway.
    internal Arena(long blockBytes, int scratchWords, int threads, bool touch = true) : base(true)
    {
        this.blockBytes = blockBytes;
        length = checked(blockBytes + 8L * scratchWords * threads);
        ScratchWords = scratchWords;
        Threads = threads;
        if (IntPtr.Size == 4 && length > int.MaxValue - 63L) throw new OutOfMemoryException();
#if NETSTANDARD2_0
        allocation = Marshal.AllocHGlobal(new IntPtr(checked(length + 63)));
        SetHandle((IntPtr)(void*)((allocation.ToInt64() + 63) & ~63L));
#else
        nuint alignment = length >= (long)HugePage ? HugePage : 64;
        allocation = (IntPtr)NativeMemory.AlignedAlloc(checked((nuint)length), alignment);
        if (allocation == IntPtr.Zero) throw new OutOfMemoryException();
        if (alignment == HugePage) AdviseHugePages(allocation, length);
        SetHandle(allocation);
#endif
        if (touch) Clear();
        else
            for (int thread = 0; thread < threads; thread++) Sensitive.Clear(MemoryMarshal.AsBytes(Scratch(thread)));
    }

#if !NETSTANDARD2_0
    private const nuint HugePage = 2 * 1024 * 1024;

    // glibc's memset, which ZeroMemory reaches, reads every line before it writes it at arena sizes,
    // at well under half the rate of non-temporal stores. musl and Windows already clear at the
    // non-temporal rate, and there the loop is slower.
    private static readonly bool NonTemporalWipe = System.Runtime.Intrinsics.X86.Avx.IsSupported &&
        OperatingSystem.IsLinux() &&
        NativeLibrary.TryGetExport(NativeLibrary.GetMainProgramHandle(), "gnu_get_libc_version", out _);

    // Linux hosts in madvise mode give transparent huge pages only on request, and a random 1 KiB
    // block in a 64 MiB arena of 4 KiB pages misses the TLB almost every time. Advisory: a host
    // without madvise, or one that refuses, keeps small pages.
    private static void AdviseHugePages(IntPtr address, long length)
    {
        if (!OperatingSystem.IsLinux()) return;
        if (!NativeLibrary.TryGetExport(NativeLibrary.GetMainProgramHandle(), "madvise", out IntPtr madvise)) return;
        const int MadvHugePage = 14;
        ((delegate* unmanaged<IntPtr, nuint, int, int>)madvise)(address, (nuint)length, MadvHugePage);
    }
#endif

    internal int ScratchWords { get; }

    internal int Threads { get; }

    internal Span<ulong> Block(int index) => new((byte*)handle + (long)index * 1024, 128);

    internal ulong* BlockPointer(int index) => (ulong*)((byte*)handle + (long)index * 1024);

    // Starts on a 1024-byte boundary after the blocks, and ScratchWords is a multiple of 8, so every
    // thread's area keeps the arena's 64-byte alignment.
    internal Span<ulong> Scratch(int thread) =>
        new((byte*)handle + blockBytes + 8L * ScratchWords * thread, ScratchWords);

    // True from the start of a hash until the wipe after it. Release skips a second wipe of an
    // arena that the last hash's own wipe already left zero.
    private volatile bool dirty;

    internal void MarkDirty() => dirty = true;

    internal void Clear()
    {
        long offset = 0;
#if !NETSTANDARD2_0
        // The blocks: 1 KiB each, from a 64-byte-aligned start.
        if (NonTemporalWipe)
        {
            Sensitive.ClearNonTemporal((byte*)handle, blockBytes);
            offset = blockBytes;
        }
#endif
        while (offset < length)
        {
            int count = (int)Math.Min(length - offset, int.MaxValue);
            Sensitive.Clear(new Span<byte>((byte*)handle + offset, count));
            offset += count;
        }
        dirty = false;
    }

    protected override bool ReleaseHandle()
    {
        if (dirty) Clear();
#if NETSTANDARD2_0
        Marshal.FreeHGlobal(allocation);
#else
        NativeMemory.AlignedFree((void*)allocation);
#endif
        allocation = IntPtr.Zero;
        return true;
    }
}
