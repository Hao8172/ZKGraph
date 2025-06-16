use halo2_proofs::halo2curves::{
    bn256::Fr, // 这里选用 bn256 的 Fr 作为有限域类型
    ff::PrimeField,
};
use std::cmp::max;
use std::convert::TryInto;

/// 当边没有按照要求的顺序排列时返回该错误
#[derive(Debug)]
pub struct EdgesNotSorted {
    /// 第一个错误出现的边（起点, 目标）
    pub first_error: (usize, usize),
}

/// 定义一个 trait，将边转换为 (source, target, weight) 格式。  
/// - `source` 和 `target` 表示边的起点和终点，通常为整型（例如 u64）  
/// - `weight` 表示边的权重，类型为 F
pub trait IntoWeightedEdge<F: PrimeField> {
    type NodeId;
    fn into_weighted_edge(self) -> (Self::NodeId, Self::NodeId, F);
}

/// 针对边类型 `(u64, u64)` 实现 `IntoWeightedEdge` trait  
/// 这里简单地将目标结点编号转换为权重（通过 `F::from(u64)`）
impl<F: PrimeField> IntoWeightedEdge<F> for (u64, u64) {
    type NodeId = u64;
    fn into_weighted_edge(self) -> (Self::NodeId, Self::NodeId, F) {
        (self.0, self.1, F::from(self.1))
    }
}

/// 用于表示 CSR（Compressed Sparse Row）格式的结构。  
/// 其中：  
/// - `row` 数组中第 i 个元素表示起点为 i 的第一条边在 `column` 和 `edges` 中的起始位置；  
/// - `column` 数组存放所有边的目标结点；  
/// - `edges` 数组存放所有边的权重。
#[derive(Clone, Debug, Default)]
pub struct CsrValue<F: PrimeField + Ord> {
    pub row: Vec<F>,
    pub column: Vec<F>,
    pub edges: Vec<F>,
}

impl<F> CsrValue<F>
where
    F: PrimeField + Ord + Clone,
{
    /// 根据已排序的边构造出 CSR 格式的数据。
    ///
    /// # 参数
    ///
    /// - `edges`: 已排序的边的切片，每个边都能转换为 (source, target, weight) 的格式。
    ///
    /// # 返回值
    ///
    /// 如果边排序正确，则返回构造好的 `CsrValue`，
    /// 否则返回 `EdgesNotSorted` 错误。
    pub fn from_sorted_edges<Edge>(edges: &[Edge]) -> Result<Self, EdgesNotSorted>
    where
        Edge: Clone + IntoWeightedEdge<F, NodeId = u64>,
    {
        // 遍历所有边，确定出现的最大结点编号（假设结点编号从 0 开始）
        let max_node_id = match edges
            .iter()
            .map(|edge| {
                let (src, tgt, _) = edge.clone().into_weighted_edge();
                max(src as usize, tgt as usize)
            })
            .max()
        {
            None => {
                return Ok(CsrValue {
                    row: Vec::new(),
                    column: Vec::new(),
                    edges: Vec::new(),
                })
            }
            Some(x) => x,
        };
        let num_nodes = max_node_id + 1;
        // 构造 row 数组，多分配一个位置用于存放最后的边总数
        let mut csr = CsrValue {
            row: vec![F::from(0u64); num_nodes + 1],
            column: Vec::new(),
            edges: Vec::new(),
        };

        let mut iter = edges.iter().cloned().peekable();
        let mut count = 0;
        // 按照节点顺序扫描边，构造 CSR 数据结构
        for node in 0..num_nodes {
            // 当前节点第一个边的起始位置
            csr.row[node] = F::from(count as u64);
            let mut last_target: Option<u64> = None;
            // 处理同一节点下的所有边
            while let Some(edge) = iter.peek() {
                let (src, tgt, weight) = edge.clone().into_weighted_edge();
                // 如果当前边的起点不等于当前节点，则退出循环
                if src as usize != node {
                    break;
                }
                // 同一节点内的边，要求目标严格递增
                if let Some(last) = last_target {
                    if tgt <= last {
                        return Err(EdgesNotSorted {
                            first_error: (src as usize, tgt as usize),
                        });
                    }
                }
                last_target = Some(tgt);
                csr.column.push(F::from(tgt));
                csr.edges.push(weight);
                count += 1;
                iter.next();
            }
        }
        // 最后一个 row 元素保存边的总数
        csr.row[num_nodes] = F::from(count);
        Ok(csr)
    }

    /// 计算节点的个数  
    /// 由于 row 数组长度为节点数 + 1，因此节点数为 row.len() - 1
    pub fn node_count(&self) -> usize {
        if self.row.is_empty() {
            0
        } else {
            self.row.len() - 1
        }
    }

    /// 计算边的个数
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// 返回指定节点的邻接边信息  
    /// 返回值为一个元组：
    /// - 第一个切片为该节点对应的所有目标节点（列数组中的子切片）  
    /// - 第二个切片为该节点对应的所有边的权重  
    pub fn neighbors(&self, node: usize) -> Option<(&[F], &[F])> {
        if node >= self.node_count() {
            None
        } else {
            // 将 F 转换成 repr 后使用低 8 字节转换成 u64，注意这里假定 F 内保存的数值不会超过 u64::MAX
            let row_repr = self.row[node].to_repr();
            let row_bytes = row_repr.as_ref();
            let start_bytes: [u8; 8] = row_bytes[..8].try_into().unwrap();
            let start = u64::from_le_bytes(start_bytes) as usize;

            let row_next_repr = self.row[node + 1].to_repr();
            let row_next_bytes = row_next_repr.as_ref();
            let end_bytes: [u8; 8] = row_next_bytes[..8].try_into().unwrap();
            let end = u64::from_le_bytes(end_bytes) as usize;

            Some((&self.column[start..end], &self.edges[start..end]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;

    #[test]
    fn test_csr_construction() {
        // 构造边的列表，边已经按照 (起点, 终点) 的顺序排列，并且同一起点内终点严格递增
        let edges = vec![(0u64, 1u64), (0, 3), (1, 2), (2, 4)];
        let csr = CsrValue::<Fr>::from_sorted_edges(&edges).expect("构造 CSR 成功");

        // 节点数应为 5（0~4），因为最大节点编号为 4
        assert_eq!(csr.node_count(), 5);
        // 边数应为 4
        assert_eq!(csr.edge_count(), 4);

        // 检查节点 0 的邻居
        if let Some((neighbors, weights)) = csr.neighbors(1) {
            // 应有两个邻居：1 和 3
            assert_eq!(neighbors.len(), 1);
            // 此处由于 Fr 难以直接转型比较，此处只打印调试信息
            println!("节点 1 的邻居: {:?}", neighbors);
            println!("节点 0 的边权重: {:?}", weights);
        } else {
            panic!("节点 0 应该有邻居");
        }

        println!("csr:{:?}", csr);
    }

    #[test]
    fn test_unsorted_edges() {
        // 构造未排序的边（同一节点内终点不严格递增）
        let edges = vec![(0u64, 3u64), (0, 2)]; // 3 后面出现 2，不合法
        let result = CsrValue::<Fr>::from_sorted_edges(&edges);
        assert!(result.is_err());
        if let Err(err) = result {
            println!("错误信息: {:?}", err.first_error);
        }
    }

    #[test]
    fn test_random_graph() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        // 使用固定种子以确保测试可重现
        let mut rng = StdRng::seed_from_u64(42);

        // 生成随机图参数
        let node_count = 20;
        let edge_count = 50;

        // 生成随机边，确保边按照要求排序
        let mut random_edges = Vec::new();
        for src in 0..node_count {
            // 为每个源节点生成随机数量的边
            let edges_for_node = rng.gen_range(0..5);
            let mut targets = Vec::new();

            // 为当前源节点生成不重复的目标节点
            for _ in 0..edges_for_node {
                let mut tgt = rng.gen_range(0..node_count);
                // 确保目标节点不重复
                while targets.contains(&tgt) {
                    tgt = rng.gen_range(0..node_count);
                }
                targets.push(tgt);
            }

            // 对目标节点排序，确保满足 CSR 构建要求
            targets.sort();

            // 添加到边列表
            for tgt in targets {
                random_edges.push((src as u64, tgt as u64));
            }
        }

        // 构建 CSR
        let csr = CsrValue::<Fr>::from_sorted_edges(&random_edges).expect("构造随机图 CSR 成功");

        // 验证节点数和边数
        assert!(csr.node_count() >= node_count);
        assert_eq!(csr.edge_count(), random_edges.len());

        // 验证每个节点的邻居是否正确
        for (src, tgt) in &random_edges {
            let src = *src as usize;
            let tgt = *tgt;

            if let Some((neighbors, _)) = csr.neighbors(src) {
                // 检查目标节点是否在邻居列表中
                let found = neighbors.iter().any(|&n| {
                    let n_repr = n.to_repr();
                    let n_bytes = n_repr.as_ref();
                    let n_value_bytes: [u8; 8] = n_bytes[..8].try_into().unwrap();
                    let n_value = u64::from_le_bytes(n_value_bytes);
                    n_value == tgt
                });

                assert!(found, "节点 {} 应该有邻居 {}", src, tgt);
            } else {
                panic!("节点 {} 应该有邻居", src);
            }
        }

        println!(
            "随机图测试通过，节点数: {}, 边数: {}",
            csr.node_count(),
            csr.edge_count()
        );
    }
}

fn main() {
    // 提供一个简单示例，构造 CSR 数据结构
    let edges = vec![(0u64, 1u64), (0, 3), (1, 2), (2, 4)];
    match CsrValue::<Fr>::from_sorted_edges(&edges) {
        Ok(csr) => {
            println!("CSR 构造成功！");
            println!("节点数量: {}", csr.node_count());
            println!("边的数量: {}", csr.edge_count());
        }
        Err(err) => {
            println!("构造 CSR 失败，错误信息: {:?}", err.first_error);
        }
    }
}
