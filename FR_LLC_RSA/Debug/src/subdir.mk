################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/spy.c 

OBJS += \
./src/spy.o 

C_DEPS += \
./src/spy.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: IoT Poky 32-Bit GCC Compiler'
	docker exec -i 3d08857d7b8a9a268bad8f93ca644a1aa1312a8acb73f84c637cbb92e398334b /bin/bash -c "cd /workspace/FR_LLC_RSA/Debug && i586-poky-linux-gcc -I/usr/include/mraa -O0 -g3 -Wall -c -fmessage-length=0 --sysroot="" -m32 -march=i586 -c -ffunction-sections -fdata-sections -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<""
	@echo 'Finished building: $<'
	@echo ' '


