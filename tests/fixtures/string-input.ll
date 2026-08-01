@.str.alpha = private unnamed_addr constant [6 x i8] c"hello\00", align 1
@.str.beta = private unnamed_addr constant [12 x i8] c"static gang\00", align 1

declare i32 @puts(ptr)

define i32 @main() {
entry:
  %first = call i32 @puts(ptr @.str.alpha)
  %second = call i32 @puts(ptr @.str.beta)
  ret i32 0
}
