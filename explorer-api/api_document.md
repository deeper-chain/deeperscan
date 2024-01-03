## 接口文档：DataEventResource

### 概述

`DataEventResource` 接口提供了查询特定地址下的交易记录的功能。它支持基本查询、带时间范围的查询以及分页功能。

### 基本信息

- **URL**: `/api/v1/deeper/adsc_transfer`
- **方法**: `GET`
- **认证**: 无（如果需要，可以添加认证机制）

### 请求参数

| 参数名       | 类型   | 描述                              | 必须 | 示例值                                          |
|-------------|-------|----------------------------------|------|-------------------------------------------------|
| `address`   | 字符串 | 查询交易的地址。                | 是   | `5EoBP9qottfQVbcicWUR9uvTiaeYJKkcQrRgeEL8Q1nysEWY` |
| `start_time`| 整数   | 查询时间范围的开始（Unix时间戳）   | 否   | `1704067200`（对应于 2024-01-01 00:00:00 UTC）  |
| `end_time`  | 整数   | 查询时间范围的结束（Unix时间戳）   | 否   | `1704326399`（对应于 2024-01-03 23:59:59 UTC）  |
| `page`      | 整数   | 请求的页码数，用于分页。         | 否   | `2`                                             |
| `limit`     | 整数   | 每页显示的记录数。              | 否   | `10`                                            |

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

1. **基本查询特定地址（SS58地址）**
   ```
   GET https://www.deeperscan.io/api/v1/deeper/adsc_transfer?address=5EoBP9qottfQVbcicWUR9uvTiaeYJKkcQrRgeEL8Q1nysEWY
   ```

2. **基本查询特定地址（公钥地址）**
   ```
   GET https://www.deeperscan.io/api/v1/deeper/adsc_transfer?address=0x78dd6eecd6e6b3fbc87b54d3e8c7d58296a4beb9ccf66ba923b637b324b7e41d
   ```

3. **带时间范围的查询**
   ```
   GET https://www.deeperscan.io/api/v1/deeper/adsc_transfer?address=5EoBP9qottfQVbcicWUR9uvTiaeYJKkcQrRgeEL8Q1nysEWY&start_time=1704067200&end_time=1704326399
   ```

4. **特定地址的分页查询**
   ```
   GET https://www.deeperscan.io/api/v1/deeper/adsc_transfer?address=0x78dd6eecd6e6b3fbc87b54d3e8c7d58296a4beb9ccf66ba923b637b324b7e41d&page=1&limit=5
   ```

5. **带时间范围和分页的复合查询**
   ```
   GET https://www.deeperscan.io/api/v1/deeper/adsc_transfer?address=0x78dd6eecd6e6b3fbc87b54d3e8c7d58296a4beb9ccf66ba923b637b324b7e41d&start_time=1704067200&end_time=1704326399&page=1&limit=2
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

1. **参数格式和有效性**：确保所有传递的参数，特别是 `address`，遵循预期的格式和数据类型。无效或格式不正确的参数可能导致查询失败或返回不正确的数据。

2. **时间戳处理**：时间戳参数 `start_time` 和 `end_time` 应为有效的 Unix 时间戳。请确认提供的时间戳正确地反映了所需的查询时间范围，并考虑时区转换（如果适用）。

3. **无时间范围时的默认行为**：如果未提供时间范围参数（即 `start_time` 和 `end_time`），接口将返回指定地址的所有交易记录。请注意，这可能涉及大量数据，因此请谨慎使用。

4. **分页逻辑**：分页参数 `page` 和 `limit` 用于控制分页行为。如果这些参数没有被提供，默认值分别为 `1`（第一页）和 `10`（每页10条记录）。请注意，请求页数超过实际页数时，将返回空数据。

5. **数据完整性和延迟**：由于区块链数据的性质，最新的交易记录可能会有一定的上链和处理延迟。因此，最近的交易可能不会立即出现在查询结果中。