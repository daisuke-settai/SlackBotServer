import cv2
import numpy
import logging
import config

TMP_IMAGE_DIR = config.APP_ROOT_PATH + '/tmp/image'
logging.basicConfig(level=logging.INFO)

BLOCK_HEIGHT = 100
BLOCK_WIDTH = 100

# table_data: [[level]] => e.g., [[0,2,3,0,0,0,0], ...]
# levelによって濃淡を決定: とりあえず0~10, 255 * level * 0.1
# OUT: FILE FULLPATH
def make_table_oneweek(table_data, output_filename, max_level, title):
    table_rows = len(table_data)
    logging.debug(type(table_data))
    if table_data == []:
        return ''
    table_colomns = len(table_data[0])
    for row in table_data:
        if len(row) != table_colomns:
            return ''
        if len(row[0]) != 3:
            return ''
    logging.debug(f"table_row: {table_rows}, table_colomn: {table_colomns}")

    for i, row in enumerate(table_data):
        for j, level in enumerate(row):
            if level[0] == 0:
                table_data[i][j][0] = 255
                table_data[i][j][1] = 255
                table_data[i][j][2] = 255
            else:
                table_data[i][j][0] = 255 - (255 * level[0]) / max_level
                table_data[i][j][1] = 255
                table_data[i][j][2] = 255 - (255 * level[2]) / max_level
    zoomed_image = table_data.repeat(BLOCK_HEIGHT, axis=0).repeat(BLOCK_WIDTH, axis=1)
    # 罫線
    y_step=BLOCK_HEIGHT
    x_step=BLOCK_WIDTH 
    img_y,img_x=zoomed_image.shape[:2]
    zoomed_image[0:img_y:y_step, :, :] = 0
    zoomed_image[:, 0:img_x:x_step, :] = 0

    table_image_width = table_colomns * BLOCK_WIDTH
    table_image_height = table_rows * BLOCK_HEIGHT

    # 余白を追加してキャプションなどを追加
    space_x = 120
    space_y = 100
    new_image_width = table_image_width + space_x
    new_image_height = table_image_height + space_y
    new_img = cv2.resize(numpy.zeros((1,1,3)), (new_image_width, new_image_height))
    new_img.fill(255)
    new_img[space_y:new_image_height, space_x:new_image_width] = zoomed_image

    cv2.putText(new_img, title, (10, 40), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2, cv2.LINE_4)
    weekdays = ['Mon.', 'Tue.', 'Wed.', 'Thu.', 'Fri.', 'Sat.', 'Sun.']
    for i, weekday in enumerate(weekdays):
        cv2.putText(new_img, weekday, (int(space_x + BLOCK_WIDTH * (0.3 + i)), int(space_y * 0.9)), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2, cv2.LINE_4)
    for i in range(table_rows):
        time = str(int(24 / table_rows) * i).zfill(2) + ':00'
        cv2.putText(new_img, time, (int(space_x * 0.3), int(space_y + BLOCK_HEIGHT * (0.2 + i))), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2, cv2.LINE_4)

    cv2.imwrite(f"{TMP_IMAGE_DIR}/{output_filename}.png",  new_img)

    return f"{TMP_IMAGE_DIR}/{output_filename}.png"


# table_data: [[level]] => e.g., [[0,2,3,0,0,0,0], ...]
# levelによって濃淡を決定: とりあえず0~10, 255 * level * 0.1
# OUT: FILE FULLPATH
# 各マスの右下に何時間いたのかを表示 (e.g., 180h)
# titleに[active: 20days]表示を追加
def make_table(table_data, output_filename, max_level, titles):
    table_rows = len(table_data)
    logging.debug(type(table_data))
    if table_data == []:
        return ''
    table_colomns = len(table_data[0])
    for row in table_data:
        if len(row) != table_colomns:
            return ''
        if len(row[0]) != 3:
            return ''
    logging.debug(f"table_row: {table_rows}, table_colomn: {table_colomns}")

    table_image = numpy.zeros((table_rows, table_colomns, 3))
    for i, row in enumerate(table_data):
        for j, level in enumerate(row):
            if level[0] == 0:
                table_image[i][j][0] = 255
                table_image[i][j][1] = 255
                table_image[i][j][2] = 255
            else:
                table_image[i][j][0] = 255 - (255 * level[0]) / max_level
                table_image[i][j][1] = 255
                table_image[i][j][2] = 255 - (255 * level[2]) / max_level
    zoomed_image = table_image.repeat(BLOCK_HEIGHT, axis=0).repeat(BLOCK_WIDTH, axis=1)
    # 各マスに時間を追加
    for y, row in enumerate(table_data):
        for x, level in enumerate(row):
            if level[0] != 0:
                cv2.putText(zoomed_image, f"{level[0]}h", (int(BLOCK_WIDTH * x + 10), int(BLOCK_HEIGHT * (y + 1) - 10)), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 1, cv2.LINE_4)
    # 罫線
    y_step=BLOCK_HEIGHT
    x_step=BLOCK_WIDTH
    img_y,img_x=zoomed_image.shape[:2]
    zoomed_image[0:img_y:y_step, :, :] = 0
    zoomed_image[:, 0:img_x:x_step, :] = 0

    table_image_width = table_colomns * BLOCK_WIDTH
    table_image_height = table_rows * BLOCK_HEIGHT

    # 余白を追加してキャプションなどを追加
    space_x = 120
    space_y = 60 + (40 * len(titles))
    new_image_width = table_image_width + space_x
    new_image_height = table_image_height + space_y
    new_img = cv2.resize(numpy.zeros((1,1,3)), (new_image_width, new_image_height))
    new_img.fill(255)
    new_img[space_y:new_image_height, space_x:new_image_width] = zoomed_image

    for i, title in enumerate(titles):
        cv2.putText(new_img, title, (10, 40 * (i + 1)), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2, cv2.LINE_4)
    weekdays = ['Mon.', 'Tue.', 'Wed.', 'Thu.', 'Fri.', 'Sat.', 'Sun.']
    for i, weekday in enumerate(weekdays):
        cv2.putText(new_img, weekday, (int(space_x + BLOCK_WIDTH * (0.3 + i)), int(space_y * 0.9)), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2, cv2.LINE_4)
    for i in range(table_rows):
        time = str(int(24 / table_rows) * i).zfill(2) + ':00'
        cv2.putText(new_img, time, (int(space_x * 0.3), int(space_y + BLOCK_HEIGHT * (0.2 + i))), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2, cv2.LINE_4)

    cv2.imwrite(f"{TMP_IMAGE_DIR}/{output_filename}.png",  new_img)

    return f"{TMP_IMAGE_DIR}/{output_filename}.png"
