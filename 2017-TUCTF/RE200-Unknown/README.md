# Unknown

**Category:** Reverse Engineering
**Points:** 200

**Description:**
> Diggin through some old files we discovered this binary. Although despite our inspection we can't figure out what it does. Or what it wants...

## Write Up

After downloading the binary the first thing we do is run file on it:
`unknown: ELF 64-bit LSB executable, x86-64...`

# Reconnaissance
Now we can dump/load the executable using our favourite disassembler.
Looking at the structure of the main function we can see a few paths:
  - A loop that can potentially branch into either a path that writes out `Nope.` to stdout or one that writes `Congraz the flag is: %s\n` to stdout.
  - Two dead paths printing either `Still nope.` or `Try again.` to stdout and immediately returning from main.

Next we can deduce a few more things from looking at the arguments main receives. 
We get one argument in `edi` and one argument in `rsi`, the linux 64bit abi dictates that the first argument to the function is passed in `rdi` and the second in `rsi`.
Assuming a standard main function like `main(int argc, char *argv[])'` we can accept `rdi` to be `argc` and rsi to be `argv[]`. We can confirm this by checking how the arguments
are used:
	
	# for argc
	mov     [rbp-20], edi
	cmp     dword ptr [rbp-20], 2
	jz      short loc_Try_Again

	# for argv[]
	mov     [rbp-32], rsi
	mov     rax, [rbp-32]
	add     rax, 8
	mov     rax, [rax]
	mov     rdi, rax
	call    __strlen

Because we're on 64 bit we have to add 8 to the pointer to argv to get the second element from the array (the first being the exectuable name).
We then pass argv[1] (whatever argument we would give when executing the binary) to strlen and compare the result to a hardcoded value of 56, if it doesn't equal 
56 we jump to the bad path printing `Still nope.` and exit.

Knowing now we're expected to pass a 56 character long string as argument to the binary we can start looking at what the input is used for.
Right before the loop it sets 2 variables it needs for the loop:
	
	# load the first command line argument to the binary (char *) into [rbp-8]
	mov     rax, [rbp-32]
	mov     rax, [rax+8]
	mov     [rbp-8], rax

	# Initialise [rbp-12] (iterator) to 0
	mov     dword ptr [rbp-12], 0

We then start looping until the iterator becomes equal to the hardcoded string length akin to `for (int i = 0; i < 56; ++i)`.
In the loop it calls a function which sets a global variable to 1 if it returns 0 (false) which it later uses to determine if the password is correct or not.
Our goal is to never have that global variable be set to 1 by entering the right 56 characters.


# Reversing the password

The main function we're interested in, the one inside the loop, accepts 2 arguments: the iterator and the pointer to the char array given as a command line argument.
Attentive people will immediately spot the numbers at the top of the function which are all in the lower ascii range, when translated to ascii it contains a (not so useful) hint: `There's an easier way`.
It then seems to obtusely set a variable by doing `47 * 666` in a loop, load some variables and give them as argument to the first function, take whatever it returns and put it into the second function, then 
at last do some more calculations on whatever number is returned by the second function and compare it to a hardcoded dword.
For those interested the first function is some sort of hashing function that looks like SHA-1 and the second function takes whatever hash is given based on our input and converts it to a long where the base to translate from is given in `esi` and the pointer to the string in `rdi`.

For the input to the hashing function we can see that it only gives it one byte at a time at the index the iterator gives:
	
	mov     dl, [rdi+rsi]   ; load 1 byte from input string
	mov     [r15+8], rdx
	lea     rdi, [r15+8]    
	mov     esi, 1          ; sz of input

We now have all the information we need to write some pseudocode of the part we're interested in:
	
	for (int i = 0; i < 56; ++i)
	{
		calculated_dword = hash_and_calc(char_array[i])
		
		if (calculated_dword != hardcoded_dword_array[i])
			global_check_var = 1
	}

	if (!global_check_var)
		print "Congratz the flag is: (our input string)"

So we know that whatever the right input string is will be the flag, we know that hashing functions are one-way and (the clue here is) that hashing functions are deterministic and so are the calculations afterwards. For whatever input character we give we will always get the same calculated_dword back from the function, all that rests now is just giving every character that could possibly appear in the flag
and check the dword that that specific character generates. Keep a table of every character and their respective DWORD and translate the hardcoded dword array back to their original characters to find the
flag:

`TUCTF{w3lc0m3_70_7uc7f_4nd_7h4nk_y0u_f0r_p4r71c1p471n6!}`