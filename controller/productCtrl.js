const Products=require('../models/productModel')

// Filter products..
class APIfeatures{
    constructor(query,queryString){
        this.query=query;
        this.queryString=queryString;

    }
    filtering(){
        const queryObj={...this.queryString}
        //console.log({before:queryObj}) //before deletepage
        const excludedFields=['page','sort','limit']
        excludedFields.forEach(e1=>delete(queryObj[e1]))
        //console.log({after:queryObj}) //after delete page

        let queryStr=JSON.stringify(queryObj)
        queryStr=queryStr.replace(/\b(gte|gt|lt|lte|regex)\b/g,match=> '$'+ match)
        //console.log({queryObj,queryStr})
        //gt ,gte etc all parse and handled here..
        //regrex means matching with a particular part of string regrex(ma)=>man etc
        this.query.find(JSON.parse(queryStr))
        return this;

    }

    sorting(){ 
        if(this.queryString.sort){
            const sortBy=this.queryString.sort.split(',').join('')
            //console.log(sortBy)
            this.query=this.query.sort(sortBy) 
        }else{
            this.query=this.query.sort('-createdAt')
        }

        return this;
    }

    paginating(){
        const page=this.queryString.page *1||1
        const limit=this.queryString.limit *1||5 // 5  is we want this amount of results..
        const skip=(page-1)*limit;
        this.query=this.query.skip(skip).limit(limit)
        return this;
    }

}
const productCtrl={

    getProducts:async(req,res)=>{
        try{
           //res.json('test')
           
           const features=new APIfeatures(Products.find(),req.query)
           .filtering().sorting().paginating()
           const products=await features.query

           res.json({
            status:'sucess',
            result:products.length,
            products:products
           })


        }
        catch(err){
            return res.status(500).json({msg:err.message})

        }
    },
    createProduct:async(req,res)=>{
        try{
                  const{product_id,title,price,description,content,images,category}=req.body;
                  if(!images)return res.status(400).json({msg:"No image Uploaded"})
                  const product=await Products.findOne({product_id})
                  if(product)
                  return res.status(500).json({msg:"This already exists."})

                  const newProduct=new Products({
                    product_id,title:title.toLowerCase(),price,description,content,images,category
                  })
                  await newProduct.save()

                  res.json({msg:"created a product"})
        }
        catch(err){
            return res.status(500).json({msg:err.message})
        }
    },
    deleteProduct:async(req,res)=>{
        try{
              await Products.findByIdAndDelete(req.params.id)
             // console.log("deleted")
              res.json({msg:"deleted a product"})
        }
        catch(err){
            return res.status(500).json({msg:err.message})
        }
    },
    updateProduct:async(req,res)=>{
        try{
            const{title,price,description,content,images,category}=req.body;
            if(!images) return res.status(400).json({msg:"No image upload"})
            await Products.findOneAndUpdate({_id:req.params.id},{
                title:title.toLowerCase(),price,description,content,images,category
            })
            res.json({msg:"Updated a Product"})
        }
        catch(err){
            return res.status(500).json({msg:err.message})
        }
    }
    
}

module.exports=productCtrl