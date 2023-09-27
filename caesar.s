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
        pushl %ebp
        movl %esp, %ebp
        movl 8(%ebp), %esi  # address of string
        xorl %eax, %eax     # clear eax (our running total)

    AtoILoop:
        movb (%esi), %bl    # load next byte (character) from string into bl
        cmpb $0xa, %bl      # compare the newline character vs bl
        je AtoIDone         # if newline (end of string), we are done
        subb $'0', %bl      # convert ASCII character to integer (subtract ASCII value of '0')
        imull $10, %eax, %eax # multiply running total by 10 (shift left by one decimal place)
        addl %ebx, %eax     # add new digit to running total
        incl %esi           # move to the next character in the string
        jmp AtoILoop        # repeat the process for the next character

    AtoIDone:
        popl %ebp           # restore old base pointer
        ret                 # return, the result is in eax



    # CaesarCipher:

    CaesarCipher:
        pushl %ebp
        movl %esp, %ebp
        movl 8(%ebp), %esi       # get address of plaintext string
        movl ShiftValue, %ecx    # get shift value from the global variable

        # Ensure the shift value is within the range 0-25
        cmpl $0, %ecx
        jl ShiftNegative         # If shift value is negative, jump to ShiftNegative

    CaesarLoop:
        movb $0, %bl             # Clear the uppercase flag
        movb (%esi), %al         # load next byte (char) from plaintext into al
        testb %al, %al           # test if it's the null terminator (end of str)
        je CaesarDone            # if zero (end of string), we are done

        cmpb $'A', %al           # check if character is uppercase
        jl NotUppercase          # if below 'A', not an uppercase alphabetic char
        cmpb $'Z', %al           # check if character is uppercase
        jg NotUppercase          # if above 'Z', not an uppercase alphabetic char
        movb $1, %bl             # Set uppercase flag
        subb $'A', %al           # convert to 0-25
        addb %cl, %al            # add shift value
        jmp Mod26                # jump to Mod26 to perform modulo operation

    NotUppercase:
        # handler for cases of NOT upper case
        cmpb $'a', %al           # check if character is lowercase
        jl NotAlpha              # if below 'a', not an alphabetic char
        cmpb $'z', %al           # check if character is lowercase
        jg NotAlpha              # if above 'z', not an alphabetic char
        subb $'a', %al           # convert to 0-25
        addb %cl, %al            # add shift value
        jmp Mod26                # jump to Mod26 to perform modulo operation

    Mod26:
        # handle wrapping for positive shift values
        cmpb $26, %al        # compare with 26
        jb NoWrap            # if below 26, no wrapping needed
        subb $26, %al        # subtract 26 if above or equal to 26

    NoWrap:
        # handle wrapping for negative shift values
        cmpb $0, %al         # compare with 0
        jge UpdateChar       # if greater or equal to 0, jump to UpdateChar
        addb $26, %al        # add 26 if negative

    UpdateChar:
        # hanldes how the current char is to be processed
        test %ebx, %ebx          # Check if uppercase flag is set
        jnz IsUppercase          # If set, jump to IsUppercase
        addb $'a', %al           # convert back to 'a'-'z'
        jmp CharDone             # repeat the process for the next char

    IsUppercase:
        # handler for cases of upper case
        addb $'A', %al # convert back to 'A'-'Z'

    CharDone:
        # handles the processing of hte current char and tells point to move to the nxt char
        movb %al, (%esi)         # store possibly-modified char back into str
        incl %esi                # move to the next char in the str
        jmp CaesarLoop           # repeat the process for the next char

    ShiftNegative:
        # Handle a negative shift value (shift left by the absolute value of the shift value)
        negl %ecx                # Negate the shift value
        jmp CaesarLoop           # repeat the process for the next char

    NotAlpha:
        # handles non alphabetic chars, used est cases expected output to determin behavior 
        incl %esi                # move to the next char in the str
        jmp CaesarLoop           # repeat the process for the next char

    CaesarDone:
        popl %ebp                # restore the old base pointer
        ret                      # return, the modified string is at the original address



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
        pushl $intBuffer       # Push the address of the buffer containing the string to the stack
        call AtoI              # Call the AtoI function
        addl $4, %esp          # adding 4 to the stack pointer %esp
        movl %eax, ShiftValue  # moves that int value from the %eax register into the global var ShiftValue

        # Ensure the shift value is within the range 0-25
        movl ShiftValue, %eax
        xorl %edx, %edx  # Clear edx for division
        movl $26, %ecx   # Set divisor to 26
        divl %ecx        # eax = eax / ecx, edx = eax % ecx
        movl %edx, ShiftValue

        # Perform the caesar cipheR
        # FILL IN HERE
        pushl ShiftValue  # Push the shift value as an argument
        pushl $buffer     # Push the buffer as an argument
        call CaesarCipher
        addl $8, %esp     # Remove the arguments from the stack


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
