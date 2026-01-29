#!/usr/bin/env python3
"""
Benchmark script for secertcert certificate generation.

Measures time to generate certificates for various data sizes:
- 10 characters
- 100 characters
- 1,000 characters
- 10,000 characters

Usage:
    python benchmark.py
    python benchmark.py --larger    # Include 100K and 1M tests
"""

import argparse
import shutil
import tempfile
import time
from typing import List, Tuple

import secertcert


def format_time(seconds: float) -> str:
    """Format time in human-readable format."""
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.2f} \u03bcs"
    elif seconds < 1:
        return f"{seconds * 1_000:.2f} ms"
    elif seconds < 60:
        return f"{seconds:.2f} s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"


def benchmark_size(data_size: int, mode: str = "keys", encrypt: bool = False) -> Tuple[float, int]:
    """
    Benchmark certificate generation for given data size.

    Returns:
        Tuple of (elapsed_time_seconds, num_chunks)
    """
    data = b"X" * data_size

    # Create temp directory
    temp_dir = tempfile.mkdtemp()

    try:
        start_time = time.perf_counter()

        file_paths, _ = secertcert.generate_certificates(
            data=data,
            output_dir=temp_dir,
            mode=mode,
            verbose=False,
            encrypt=encrypt
        )

        elapsed = time.perf_counter() - start_time
        num_chunks = len(file_paths)

        return elapsed, num_chunks

    finally:
        shutil.rmtree(temp_dir)


def run_benchmark(sizes: List[int], mode: str = "keys", encrypt: bool = False) -> None:
    """Run benchmarks for multiple sizes."""

    print("=" * 70)
    print(f"secertcert Benchmark")
    print(f"Mode: {mode}")
    print(f"Encryption: {'enabled' if encrypt else 'disabled'}")
    print("=" * 70)
    print()

    # Header
    print(f"{'Size':<15} {'Chunks':<10} {'Time':<15} {'Time/Chunk':<15} {'Rate':<15}")
    print("-" * 70)

    results = []

    for size in sizes:
        # Format size for display
        if size >= 1_000_000:
            size_str = f"{size // 1_000_000}M chars"
        elif size >= 1_000:
            size_str = f"{size // 1_000}K chars"
        else:
            size_str = f"{size} chars"

        elapsed, num_chunks = benchmark_size(size, mode=mode, encrypt=encrypt)

        time_str = format_time(elapsed)
        time_per_chunk = format_time(elapsed / num_chunks) if num_chunks > 0 else "N/A"

        # Calculate rate (chars per second)
        rate = size / elapsed if elapsed > 0 else 0
        if rate >= 1_000_000:
            rate_str = f"{rate / 1_000_000:.1f} M/s"
        elif rate >= 1_000:
            rate_str = f"{rate / 1_000:.1f} K/s"
        else:
            rate_str = f"{rate:.1f} /s"

        print(f"{size_str:<15} {num_chunks:<10} {time_str:<15} {time_per_chunk:<15} {rate_str:<15}")

        results.append({
            "size": size,
            "chunks": num_chunks,
            "elapsed": elapsed,
            "rate": rate
        })

    print("-" * 70)
    print()

    # Summary statistics
    if len(results) > 1:
        avg_time_per_chunk = sum(r["elapsed"] / r["chunks"] for r in results) / len(results)
        print(f"Average time per chunk: {format_time(avg_time_per_chunk)}")
        print(f"Chunk payload size: {secertcert.CHUNK_PAYLOAD_SIZE} bytes")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark secertcert certificate generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python benchmark.py                      # Basic benchmark (10-10K chars)
    python benchmark.py --larger             # Include 100K and 1M tests
    python benchmark.py --mode x509          # Test X.509 certificate mode
    python benchmark.py --encrypt            # Test with encryption enabled
        """
    )

    parser.add_argument("--larger", action="store_true",
                        help="Include larger test sizes (100K and 1M chars)")
    parser.add_argument("--mode", choices=["keys", "x509"], default="keys",
                        help="Generation mode (default: keys)")
    parser.add_argument("--encrypt", action="store_true",
                        help="Enable encryption")

    args = parser.parse_args()

    # Base sizes
    sizes = [10, 100, 1_000, 10_000]

    # Add larger sizes if requested
    if args.larger:
        sizes.extend([100_000, 1_000_000])
        print("Including 100K and 1M tests (this may take a while)...")
        print()

    run_benchmark(sizes, mode=args.mode, encrypt=args.encrypt)


if __name__ == "__main__":
    main()
