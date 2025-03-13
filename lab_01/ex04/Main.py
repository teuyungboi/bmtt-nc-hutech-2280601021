from QuanLySinhVien import QuanLySinhVien

qlsv = QuanLySinhVien()

while True:
    print("\nCHƯƠNG TRÌNH QUẢN LÝ SINH VIÊN")
    print("*********** MENU **********")
    print("1. Thêm sinh viên.")
    print("2. Cập nhật thông tin sinh viên theo ID.")
    print("3. Xóa sinh viên theo ID.")
    print("4. Tìm kiếm sinh viên theo tên.")
    print("5. Sắp xếp sinh viên theo điểm trung bình.")
    print("6. Sắp xếp sinh viên theo tên chuyên ngành.")
    print("7. Hiển thị danh sách sinh viên.")
    print("0. Thoát")
    
    key = int(input("Nhập tùy chọn: "))

    if key == 1:
        print("\n1. Thêm sinh viên.")
        qlsv.nhapSinhVien()
        print("\nThêm sinh viên thành công!")

    elif key == 2:
        if qlsv.soLuongSinhVien() > 0:
            print("\n2. Cập nhật thông tin sinh viên.")
            print("\nNhập ID: ")
            ID = int(input())
            qlsv.updateSinhVien(ID)
        else:
            print("\nDanh sách sinh viên trống!")

    elif key == 3:
        if qlsv.soLuongSinhVien() > 0:
            print("\n3. Xóa sinh viên.")
            print("\nNhập ID: ")
            ID = int(input())
            if qlsv.deleteById(ID):
                print(f"Sinh viên có ID {ID} đã bị xóa.")
            else:
                print(f"Sinh viên có ID {ID} không tồn tại.")
        else:
            print("\nDanh sách sinh viên trống!")

    elif key == 4:
        if qlsv.soLuongSinhVien() > 0:
            print("\n4. Tìm kiếm sinh viên theo tên.")
            print("\nNhập tên để tìm kiếm: ")
            name = input()
            searchResult = qlsv.findByName(name)
            qlsv.showSinhVien(searchResult)
        else:
            print("\nDanh sách sinh viên trống!")

    elif key == 5:
        if qlsv.soLuongSinhVien() > 0:
            print("\n5. Sắp xếp sinh viên theo điểm trung bình (GPA).")
            qlsv.sortByDiemTB()
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sách sinh viên trống!")

    elif key == 6:
        if qlsv.soLuongSinhVien() > 0:
            print("\n6. Sắp xếp sinh viên theo tên.")
            qlsv.sortByName()
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sách sinh viên trống!")

    elif key == 7:
        if qlsv.soLuongSinhVien() > 0:
            print("\n7. Hiển thị danh sách sinh viên.")
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sách sinh viên trống!")

    elif key == 0:
        print("\nBạn đã chọn thoát chương trình!")
        break

    else:
        print("\nKhông có chức năng này!")
        print("Hay chọn chức năng trong hộp menu.")
        