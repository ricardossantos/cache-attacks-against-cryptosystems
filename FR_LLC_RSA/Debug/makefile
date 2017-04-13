################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: FR_LLC_RSA

# Tool invocations
FR_LLC_RSA: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: IoT Poky 32-Bit GCC Linker'
	docker exec -i 3d08857d7b8a9a268bad8f93ca644a1aa1312a8acb73f84c637cbb92e398334b /bin/bash -c "cd /workspace/FR_LLC_RSA/Debug && i586-poky-linux-gcc --sysroot="" -o "FR_LLC_RSA" $(OBJS) $(USER_OBJS) $(LIBS)"
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) FR_LLC_RSA
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
