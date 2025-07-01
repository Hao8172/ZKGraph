use halo2_proofs::halo2curves::{
    bn256::Fr,
    ff::PrimeField,
};
use std::cmp::max;
use std::convert::TryInto;


#[derive(Debug)]
pub struct EdgesNotSorted {
    pub first_error: (usize, usize),
}

pub trait IntoWeightedEdge<F: PrimeField> {
    type NodeId;
    fn into_weighted_edge(self) -> (Self::NodeId, Self::NodeId, F);
}

impl<F: PrimeField> IntoWeightedEdge<F> for (u64, u64) {
    type NodeId = u64;
    fn into_weighted_edge(self) -> (Self::NodeId, Self::NodeId, F) {
        (self.0, self.1, F::from(self.1))
    }
}


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

    pub fn from_sorted_edges<Edge>(edges: &[Edge]) -> Result<Self, EdgesNotSorted>
    where
        Edge: Clone + IntoWeightedEdge<F, NodeId = u64>,
    {

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
        let mut csr = CsrValue {
            row: vec![F::from(0u64); num_nodes + 1],
            column: Vec::new(),
            edges: Vec::new(),
        };

        let mut iter = edges.iter().cloned().peekable();
        let mut count = 0;
        for node in 0..num_nodes {
            csr.row[node] = F::from(count as u64);
            let mut last_target: Option<u64> = None;
            while let Some(edge) = iter.peek() {
                let (src, tgt, weight) = edge.clone().into_weighted_edge();
                if src as usize != node {
                    break;
                }
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
        csr.row[num_nodes] = F::from(count);
        Ok(csr)
    }

    pub fn node_count(&self) -> usize {
        if self.row.is_empty() {
            0
        } else {
            self.row.len() - 1
        }
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
 
    pub fn neighbors(&self, node: usize) -> Option<(&[F], &[F])> {
        if node >= self.node_count() {
            None
        } else {
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
