## 接口文档：DataEventResource

### 概述

`DataEventResource` 接口提供了查询特定地址下的交易记录的功能。支持基本查询以及带时间范围的查询。

### 基本信息

- **URL**: `/api/v1/deeper/adsc_transfer`
- **方法**: `GET`
- **认证**: 无（如果需要，可以添加认证机制）

### 请求参数

| 参数名       | 类型   | 描述                        | 必须 | 示例值                                          |
|-------------|-------|----------------------------|------|-------------------------------------------------|
| `address`   | 字符串 | 查询交易的地址。          | 是   | `5EoBP9qottfQVbcicWUR9uvTiaeYJKkcQrRgeEL8Q1nysEWY` |
| `start_time`| 整数   | 查询时间范围的开始（Unix时间戳） | 否   | `1704067200`（对应于 2024-01-01 00:00:00 UTC）  |
| `end_time`  | 整数   | 查询时间范围的结束（Unix时间戳） | 否   | `1704326399`（对应于 2024-01-03 23:59:59 UTC）  |

### 响应结构

响应数据为一个 JSON 数组，每个元素包含以下字段：

| 字段名          | 类型   | 描述                 |
|----------------|-------|---------------------|
| `block_id`     | 整数   | 交易所在的区块ID。   |
| `from_address` | 字符串 | 交易的发起地址。     |
| `to_address`   | 字符串 | 交易的接收地址。     |
| `amount`       | 字符串 | 交易涉及的金额。     |
| `block_datetime` | 字符串 | 交易时间（格式："YYYY-MM-DD HH:MM:SS"）。|

### 请求示例

1. **基本查询**
   ```
   GET /api/v1/deeper/adsc_transfer?address=5EoBP9qottfQVbcicWUR9uvTiaeYJKkcQrRgeEL8Q1nysEWY
   ```

2. **带时间范围的查询**
   ```
   GET /api/v1/deeper/adsc_transfer?address=5EoBP9qottfQVbcicWUR9uvTiaeYJKkcQrRgeEL8Q1nysEWY&start_time=1704067200&end_time=1704326399
   ```

3. **查询另一个地址**
   ```
   GET /api/v1/deeper/adsc_transfer?address=0x78dd6eecd6e6b3fbc87b54d3e8c7d58296a4beb9ccf66ba923b637b324b7e41d
   ```

### 响应示例

```json
[
    {
        "block_id": 14778789,
        "from_address": "0x78dd6eecd6e6b3fbc87b54d3e8c7d58296a4beb9ccf66ba923b637b324b7e41d",
        "to_address": "0xb8681091ad55f1a449aa74de564d42d08c9ca4d523d3f32c8f19213d294f9456",
        "amount": "7625835614295000000000",
        "block_datetime": "2024-01-03 07:00:35"
    },
    // 更多交易记录...
]
```

### 注意事项

- 确保请求的 `address` 参数符合预期格式。
- 时间戳参数（`start_time` 和 `end_time`）应为有效的 Unix 时间戳。
- 如果未提供时间范围参数，将返回该地址的所有交易记录。