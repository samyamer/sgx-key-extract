# %%
import csv


Timestamp = 0
Address = 1
Mnemonics = 2
DataHi = 3
DataLo = 4
ChekBits = 5
DMsDBIs = 6
M_Address = 7
Sample = 8

def is_act(mnemonic):
    return mnemonic.startswith("  ACT - BANK ACTIVATE")

def is_write(mnemonic):
    return mnemonic.strip().startswith("WR - WRITE")


def prRed(skk): print("\033[91m{}\033[00m" .format(skk),end="")
# %%
filename = "entire_table_likely(phys_84663500).txt"
wr_addr = "2110B0"
act_addr = "207C61"
bank = "1.0"
is_row_open=False
count = 0


# %%
ndx=1
state =0
write_lines = 8
data_string=""
uncaught = ["671118"]
file_lines = []
with open(filename, mode ='r')as file:
  rows = csv.reader(file, delimiter='	')
  rows = list(rows)
  # print(rows[0])
  # print(rows[1])

  # for i in range(10):
  #   print(rows[i])
    # print(is_act(rows[i]))
    # print(len(rows))

  for row in rows:
      if(row[Sample].strip() in uncaught):
          state=1
      if(state):
          # in data collection mode
          data_string += row[DataHi].strip()+ row[DataLo].strip()
          write_lines -=1
          if(write_lines < 1): # this was the last 8 bytes switch back to checking for acts and such
              state = 0
              prRed(data_string[0:32])
              print(data_string[32:96],end="")
              prRed(data_string[96:])
              print("")
              file_lines.append(data_string+"\n")
              # prRed(data_string  + " " + str(len(data_string)))
              data_string =""
              write_lines = 8
      if(is_act(row[Mnemonics])):
          if(row[Mnemonics].strip().endswith("Logical Bank: 1.0")):
              # print("Hello")
              if(row[M_Address].strip() == act_addr):
                  # print(row[Header.Sample.value])
                  is_row_open=True
              else:
                  is_row_open=False
      elif(is_write(row[Mnemonics])):
          # print(row[Header.Sample.value])
          if(is_row_open and row[M_Address].strip() == wr_addr):
              state = 1
              # print(str(ndx) + " - " + row[Sample])
              count+=1
              if(count %2 == 0):
                  ndx+=1

print(count)

with open('filename.txt', 'a') as file:
    file.writelines(file_lines)




              # print(row[Header.Timestamp.value])




  # for lines in rows:
        # print(lines)
