.data
    PromptForPlaintext:
        .asciz  "Please enter the plaintext: "
        lenPromptForPlaintext = .-PromptForPlaintext

    PromptForShiftValue:
        .asciz  "Please enter the shift value: "
        lenPromptForShiftValue = .-PromptForShiftValue

    Newline:
        .asciz  "\n"

    ShiftValue:
        .int    0
.bss
    .comm   buffer, 102     # Buffer to read in plaintext/output ciphertext
    .comm   intBuffer, 4    # Buffer to read in shift value
                            # (assumes value is 3 digits or less)

.text

    .globl _start

    .type PrintFunction, @function
    .type ReadFromStdin, @function
    .type GetStringLength, @function
    .type AtoI, @function
    .type CaesarCipher, @function


    PrintFunction:
        pushl %ebp              # store the current value of EBP on the stack
        movl %esp, %ebp         # Make EBP point to top of stack

        # Write syscall
        movl $4, %eax           # syscall number for write()
        movl $1, %ebx           # file descriptor for stdout
        movl 8(%ebp), %ecx      # Address of string to write
        movl 12(%ebp), %edx     # number of bytes to write
        int $0x80

        movl %ebp, %esp         # Restore the old value of ESP
        popl %ebp               # Restore the old value of EBP
        ret                     # return

    ReadFromStdin:
        pushl %ebp              # store the current value of EBP on the stack
        movl %esp, %ebp         # Make EBP point to top of stack

        # Read syscall
        movl $3, %eax
        movl $0, %ebx
        movl 8(%ebp), %ecx      # address of buffer to write input to
        movl 12(%ebp), %edx     # number of bytes to write
        int  $0x80

        movl %ebp, %esp         # Restore the old value of ESP
        popl %ebp               # Restore the old value of EBP
        ret                     # return


    GetStringLength:

        # Strings which are read through stdin will end with a newline character. (0xa)
        # So look through the string until we find the newline and keep a count
        pushl %ebp              # store the current value of EBP on the stack
        movl %esp, %ebp         # Make EBP point to top of stack

        movl 8(%ebp), %esi      # Store the address of the source string in esi
        xor %edx, %edx          # edx = 0

        Count:
			inc %edx            # increment edx
            lodsb               # load the first character into eax
            cmp $0xa, %eax  	# compare the newline character vs eax
            jnz Count           # If eax != newline, loop back

        dec %edx                # the loop adds an extra one onto edx
        movl %edx, %eax          # return value

        movl %ebp, %esp         # Restore the old value of ESP
        popl %ebp               # Restore the old value of EBP
        ret                     # return


    
    #AtoI:
    
    #
    # Input is always read in as a string. 
    # This function should convert a string to an integer.
    #
    AtoI:
        pushl %ebp                  # save old base pointer
        movl %esp, %ebp             # set new base pointer
        movl 8(%ebp), %esi          # get address of string
        xorl %eax, %eax             # clear eax (our running total)

    AtoILoop:
        movb (%esi), %bl            # load next byte (character) from string into bl
        testb %bl, %bl              # test if it's the null terminator (end of string)
        je AtoIDone                 # if zero (end of string), we are done
        subb $'0', %bl              # convert ASCII character to integer (subtract ASCII value of '0')
        imull $10, %eax, %eax       # multiply running total by 10 (shift left by one decimal place)
        addl %ebx, %eax             # add new digit to running total
        incl %esi                   # move to next character in string
        jmp AtoILoop                # repeat process for next character

    AtoIDone:
        popl %ebp                   # restore old base pointer
        ret                         # return, result is in eax




    #CaesarCipher:

    #
    # Fill in code for CaesarCipher Function here
    #
    CaesarCipher:
        pushl %ebp                  # save old base pointer
        movl %esp, %ebp             # set new base pointer
        movl 8(%ebp), %esi          # get address of plaintext string
        movl 12(%ebp), %ecx         # get shift value

    CaesarLoop:
        movb (%esi), %al            # load next byte (character) from plaintext into al
        testb %al, %al              # test if it's the null terminator (end of string)
        je CaesarDone               # if zero (end of string), we are done
        cmpb $'A', %al              # check if character is uppercase
        jb NotAlpha                 # if below 'A', not an alphabetic character
        cmpb $'Z', %al              # check if character is uppercase
        ja LowerCase                # if above 'Z', it's a lowercase or not an alphabetic character

        # Handle uppercase letters
        addb %cl, %al               # add shift value
        cmpb $'Z', %al              # check if we've gone past 'Z'
        jbe NotAlpha                # if below or equal to 'Z', we are good
        subb $26, %al               # else, wrap around
        jmp NotAlpha                # move to next character

    LowerCase:
        cmpb $'a', %al              # check if character is lowercase
        jb NotAlpha                 # if below 'a', not an alphabetic character
        cmpb $'z', %al              # check if character is lowercase
        ja NotAlpha                 # if above 'z', not an alphabetic character

        # Handle lowercase letters
        addb %cl, %al               # add shift value
        cmpb $'z', %al              # check if we've gone past 'z'
        jbe NotAlpha                # if below or equal to 'z', we are good
        subb $26, %al               # else, wrap around

    NotAlpha:
        movb %al, (%esi)            # store possibly-modified character back into string
        incl %esi                   # move to next character in string
        jmp CaesarLoop              # repeat process for next character

    CaesarDone:
        popl %ebp                   # restore old base pointer
        ret                         # return, modified string is at original address


    _start:

        # Print prompt for plaintext
        pushl   $lenPromptForPlaintext
        pushl   $PromptForPlaintext
        call    PrintFunction
        addl    $8, %esp

        # Read the plaintext from stdin
        pushl   $102
        pushl   $buffer
        call    ReadFromStdin
        addl    $8, %esp

        # Print newline
        pushl   $1
        pushl   $Newline
        call    PrintFunction
        addl    $8, %esp


        # Get input string and adjust the stack pointer back after
        pushl   $lenPromptForShiftValue
        pushl   $PromptForShiftValue
        call    PrintFunction
        addl    $8, %esp

        # Read the shift value from stdin
        pushl   $4
        pushl   $intBuffer
        call    ReadFromStdin
        addl    $8, %esp

        # Print newline
        pushl   $1
        pushl   $Newline
        call    PrintFunction
        addl    $8, %esp



        # Convert the shift value from a string to an integer.
        # FILL IN HERE
        pushl $intBuffer
        call AtoI
        addl $4, %esp
        movl %eax, ShiftValue

        # Perform the caesar cipheR
        # FILL IN HERE
        movl ShiftValue, %eax
        pushl %eax
        pushl $buffer
        call CaesarCipher
        addl $8, %esp

        # Get the size of the ciphertext
        # The ciphertext must be referenced by the 'buffer' label
        pushl   $buffer
        call    GetStringLength
        addl    $4, %esp

        # Print the ciphertext
        pushl   %eax
        pushl   $buffer
        call    PrintFunction
        addl    $8, %esp

        # Print newline
        pushl   $1
        pushl   $Newline
        call    PrintFunction
        addl    $8, %esp

        # Exit the program
        Exit:
            movl    $1, %eax
            movl    $0, %ebx
            int     $0x80