import StringIO
import csv
import os

file_names=[]

for filename in os.listdir('/Users/ireneanthi/Desktop/ics_arffs/'):
    if filename.endswith(".arff"):
        file_names.append(filename)
        # print(os.path.join(directory, filename)
print(file_names)


attributes_list = []

for name in file_names:
    with open("{}".format(name)) as out:
        attributes = out.readlines()[0:104]      # The attributes in my test files are from lines 0-9
        for i in attributes:
            attributes_list.append(i)


all_individual_attributes = []

for i in attributes_list:
    if i not in all_individual_attributes:
        all_individual_attributes.append(i)     # All individual attributes



for i in all_individual_attributes:
    if "@relation" in i:
        all_individual_attributes.remove(i)
all_individual_attributes.insert(0, "@relation device_classification")



data_list = []

for name in file_names:
    with open("{}".format(name)) as out:
        data = out.readlines()[105:]         # The data in my test files are from line 10
        for i in data:
            data_list.append(i)

replace_id = []


for i in data_list:
    a = i.split(",")
    replace_id.append(a)

counter = 0

final_data_list = []

for j in replace_id:
    del j[0]
    counter += 1
    j.insert(0, counter)
    concat = ','.join(map(str,j))
    final_data_list.append(concat)



with open("final.arff", "w") as out:  # Write a final combined file
    for i in all_individual_attributes:
        out.write(i)
        out.write("\n")
    for j in final_data_list:
        out.write(j)
        out.write("\n")




print "Finished"
