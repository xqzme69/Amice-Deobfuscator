; ModuleID = 'wide.ll'
source_filename = "wide.ll"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

@.str.short = private global [8 x i16] [i16 31039, i16 -10151, i16 3329, i16 11225, i16 -12806, i16 10353, i16 -6563, i16 -19595], align 16
@.str.long = private global [7 x i32] [i32 -667911875, i32 733744433, i32 -263401963, i32 -1284163474, i32 675799698, i32 1036260360, i32 1303124183], align 4
@dec_flag_.str.short = internal global i32 0
@dec_flag_.str.long = internal global i32 0

declare void @consume(ptr) local_unnamed_addr

define void @entry() local_unnamed_addr {
  %1 = cmpxchg ptr @dec_flag_.str.short, i32 0, i32 1 acq_rel acquire, align 4
  %cmpxchg_success.i = extractvalue { i32, i1 } %1, 1
  br i1 %cmpxchg_success.i, label %rest.i.preheader, label %spin_wait.i

rest.i.preheader:                                 ; preds = %0
  %2 = load <16 x i8>, ptr @.str.short, align 16
  %3 = xor <16 x i8> %2, <i8 104, i8 121, i8 48, i8 -40, i8 101, i8 13, i8 -68, i8 43, i8 83, i8 -50, i8 76, i8 -16, i8 93, i8 56, i8 117, i8 -77>
  store <16 x i8> %3, ptr @.str.short, align 16
  store atomic i32 2, ptr @dec_flag_.str.short release, align 4
  br label %simd_xor_cipher_1772882767.exit

spin_wait.i:                                      ; preds = %0, %spin_wait.i
  %flag_val.i = load atomic i32, ptr @dec_flag_.str.short acquire, align 4
  %is_complete.i = icmp eq i32 %flag_val.i, 2
  br i1 %is_complete.i, label %simd_xor_cipher_1772882767.exit, label %spin_wait.i

simd_xor_cipher_1772882767.exit:                  ; preds = %spin_wait.i, %rest.i.preheader
  tail call void @consume(ptr nonnull @.str.short)
  %4 = cmpxchg ptr @dec_flag_.str.long, i32 0, i32 1 acq_rel acquire, align 4
  %cmpxchg_success.i1 = extractvalue { i32, i1 } %4, 1
  br i1 %cmpxchg_success.i1, label %vector.body, label %spin_wait.i2

vector.body:                                      ; preds = %simd_xor_cipher_1772882767.exit
  %wide.load = load <4 x i8>, ptr @.str.long, align 4
  %wide.load18 = load <4 x i8>, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 4), align 4
  %5 = xor <4 x i8> %wide.load, <i8 104, i8 121, i8 48, i8 -40>
  %6 = xor <4 x i8> %wide.load18, <i8 101, i8 13, i8 -68, i8 43>
  store <4 x i8> %5, ptr @.str.long, align 4
  store <4 x i8> %6, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 4), align 4
  %wide.load.1 = load <4 x i8>, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 8), align 4
  %wide.load18.1 = load <4 x i8>, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 12), align 4
  %7 = xor <4 x i8> %wide.load.1, <i8 83, i8 -50, i8 76, i8 -16>
  %8 = xor <4 x i8> %wide.load18.1, <i8 93, i8 56, i8 117, i8 -77>
  store <4 x i8> %7, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 8), align 4
  store <4 x i8> %8, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 12), align 4
  %wide.load.2 = load <4 x i8>, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 16), align 4
  %wide.load18.2 = load <4 x i8>, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 20), align 4
  %9 = xor <4 x i8> %wide.load.2, <i8 -96, i8 -30, i8 71, i8 40>
  %10 = xor <4 x i8> %wide.load18.2, <i8 8, i8 -30, i8 -59, i8 61>
  store <4 x i8> %9, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 16), align 4
  store <4 x i8> %10, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 20), align 4
  %cur.i9 = load i8, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 24), align 4
  %xored_rest.i12 = xor i8 %cur.i9, -41
  store i8 %xored_rest.i12, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 24), align 4
  %cur.i9.1 = load i8, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 25), align 1
  %xored_rest.i12.1 = xor i8 %cur.i9.1, 24
  store i8 %xored_rest.i12.1, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 25), align 1
  %cur.i9.2 = load i8, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 26), align 2
  %xored_rest.i12.2 = xor i8 %cur.i9.2, -84
  store i8 %xored_rest.i12.2, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 26), align 2
  %cur.i9.3 = load i8, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 27), align 1
  %xored_rest.i12.3 = xor i8 %cur.i9.3, 77
  store i8 %xored_rest.i12.3, ptr getelementptr inbounds nuw (i8, ptr @.str.long, i64 27), align 1
  store atomic i32 2, ptr @dec_flag_.str.long release, align 4
  br label %simd_xor_cipher_1772882767.exit17

spin_wait.i2:                                     ; preds = %simd_xor_cipher_1772882767.exit, %spin_wait.i2
  %flag_val.i3 = load atomic i32, ptr @dec_flag_.str.long acquire, align 4
  %is_complete.i4 = icmp eq i32 %flag_val.i3, 2
  br i1 %is_complete.i4, label %simd_xor_cipher_1772882767.exit17, label %spin_wait.i2

simd_xor_cipher_1772882767.exit17:                ; preds = %spin_wait.i2, %vector.body
  tail call void @consume(ptr nonnull @.str.long)
  ret void
}
